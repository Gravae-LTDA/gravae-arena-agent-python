"""
Coaching Review - Minimal S3/R2 client with AWS Signature V4.
Uses only Python stdlib (no boto3). Supports multipart upload.
"""
import hashlib
import hmac
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    from gravae_logging import get_logger
    log = get_logger('s3')
except ImportError:
    import logging
    log = logging.getLogger('s3')


class S3Client:
    """Minimal S3-compatible client for Cloudflare R2."""

    def __init__(self, endpoint, access_key_id, secret_access_key, region='auto'):
        self.endpoint = endpoint.rstrip('/')
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region

    def _sign(self, method, path, query='', headers=None, payload_hash=None):
        """Create AWS Signature V4 signed headers."""
        now = datetime.now(timezone.utc)
        date_stamp = now.strftime('%Y%m%d')
        amz_date = now.strftime('%Y%m%dT%H%M%SZ')

        if payload_hash is None:
            payload_hash = 'UNSIGNED-PAYLOAD'

        headers = headers or {}
        headers['x-amz-date'] = amz_date
        headers['x-amz-content-sha256'] = payload_hash

        # Parse host from endpoint
        parsed = urllib.parse.urlparse(self.endpoint)
        host = parsed.netloc
        headers['host'] = host

        # Canonical request
        signed_header_keys = sorted(headers.keys())
        signed_headers_str = ';'.join(signed_header_keys)
        canonical_headers = ''.join(f"{k}:{headers[k]}\n" for k in signed_header_keys)

        canonical_request = '\n'.join([
            method,
            urllib.parse.quote(path, safe='/'),
            query,
            canonical_headers,
            signed_headers_str,
            payload_hash,
        ])

        # String to sign
        credential_scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = '\n'.join([
            'AWS4-HMAC-SHA256',
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])

        # Signing key
        def _hmac_sha256(key, msg):
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()

        k_date = _hmac_sha256(f"AWS4{self.secret_access_key}".encode(), date_stamp)
        k_region = _hmac_sha256(k_date, self.region)
        k_service = _hmac_sha256(k_region, 's3')
        k_signing = _hmac_sha256(k_service, 'aws4_request')

        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

        auth_header = (
            f"AWS4-HMAC-SHA256 "
            f"Credential={self.access_key_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers_str}, "
            f"Signature={signature}"
        )

        headers['Authorization'] = auth_header
        # Remove host from headers (urllib adds it automatically)
        del headers['host']
        return headers

    def _request(self, method, path, query='', body=None, headers=None, timeout=60):
        """Make a signed request to S3/R2."""
        if body is not None:
            payload_hash = hashlib.sha256(body).hexdigest()
        else:
            payload_hash = hashlib.sha256(b'').hexdigest()

        signed_headers = self._sign(method, path, query, headers or {}, payload_hash)

        url = f"{self.endpoint}{path}"
        if query:
            url += f"?{query}"

        req = urllib.request.Request(url, data=body, method=method)
        for k, v in signed_headers.items():
            req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def create_multipart_upload(self, bucket, key, content_type='application/octet-stream'):
        """Initiate a multipart upload. Returns uploadId."""
        path = f"/{bucket}/{key}"
        query = "uploads="
        headers = {'content-type': content_type}

        status, body = self._request('POST', path, query, b'', headers)
        if status != 200:
            raise Exception(f"CreateMultipartUpload failed ({status}): {body.decode()[:200]}")

        root = ET.fromstring(body)
        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
        upload_id = root.findtext('s3:UploadId', namespaces=ns)
        if not upload_id:
            # Try without namespace
            upload_id = root.findtext('UploadId')
        if not upload_id:
            raise Exception(f"No UploadId in response: {body.decode()[:200]}")

        log.info(f"Created multipart upload: {key} -> {upload_id[:16]}...")
        return upload_id

    def upload_part(self, bucket, key, upload_id, part_number, data):
        """Upload a single part. Returns ETag."""
        path = f"/{bucket}/{key}"
        query = f"partNumber={part_number}&uploadId={urllib.parse.quote(upload_id)}"

        status, body = self._request('PUT', path, query, data, timeout=300)
        if status != 200:
            raise Exception(f"UploadPart {part_number} failed ({status}): {body.decode()[:200]}")

        # ETag is returned but we compute it from the response
        # For S3/R2, the ETag of a part is the MD5 of the part data
        etag = hashlib.md5(data).hexdigest()
        etag = f'"{etag}"'

        return etag

    def complete_multipart_upload(self, bucket, key, upload_id, parts):
        """Complete a multipart upload. parts = [(part_number, etag), ...]."""
        path = f"/{bucket}/{key}"
        query = f"uploadId={urllib.parse.quote(upload_id)}"

        # Build completion XML
        xml_parts = []
        for part_num, etag in sorted(parts):
            xml_parts.append(
                f"<Part><PartNumber>{part_num}</PartNumber><ETag>{etag}</ETag></Part>"
            )
        xml_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<CompleteMultipartUpload>'
            + ''.join(xml_parts)
            + '</CompleteMultipartUpload>'
        ).encode()

        headers = {'content-type': 'application/xml'}
        status, body = self._request('POST', path, query, xml_body, headers)
        if status != 200:
            raise Exception(f"CompleteMultipartUpload failed ({status}): {body.decode()[:200]}")

        log.info(f"Completed multipart upload: {key}")
        return True

    def abort_multipart_upload(self, bucket, key, upload_id):
        """Abort a multipart upload."""
        path = f"/{bucket}/{key}"
        query = f"uploadId={urllib.parse.quote(upload_id)}"

        status, body = self._request('DELETE', path, query)
        if status not in (200, 204):
            log.warning(f"AbortMultipartUpload warning ({status}): {body.decode()[:200]}")
        return True

    def put_object(self, bucket, key, data, content_type='application/octet-stream'):
        """Simple PUT for small files."""
        path = f"/{bucket}/{key}"
        headers = {'content-type': content_type}

        status, body = self._request('PUT', path, '', data, headers, timeout=120)
        if status != 200:
            raise Exception(f"PutObject failed ({status}): {body.decode()[:200]}")

        log.info(f"Uploaded {key} ({len(data)} bytes)")
        return True
