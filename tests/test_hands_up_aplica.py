import unittest
from unittest.mock import patch
import hands_up_module as module


class AplicaAjustesTests(unittest.TestCase):
    def aplica(self, config, resposta=(True, {})):
        posts = []
        def http(caminho, dados=None, timeout=None):
            if dados is None:
                return True, {}
            posts.append(dados)
            return resposta if any(k in dados for k in module.CHAVES_AJUSTE) else (True, {})
        with patch.object(module, '_http', side_effect=http), patch.object(module, 'status', return_value={}):
            return module.aplica(config), posts

    def test_repassa_gatilho_espera_e_dur_gesto(self):
        r, posts = self.aplica({'ativo': True, 'gatilho': 'ia', 'espera_ia_s': 300, 'dur_gesto': 2.0})
        self.assertTrue(r['ok'])
        self.assertIn({'gatilho': 'ia', 'espera_ia_s': 300, 'dur_gesto': 2.0}, posts)

    def test_cada_chave_sozinha(self):
        for cfg in ({'gatilho': 'manual'}, {'espera_ia_s': 600}, {'dur_gesto': 1.5}):
            with self.subTest(cfg=cfg):
                _, posts = self.aplica(cfg)
                self.assertEqual(posts, [cfg])

    def test_sem_ajuste_nao_manda_post_extra(self):
        _, posts = self.aplica({'ativo': True, 'quadras': {'quadra01': True}})
        self.assertEqual(posts, [{'ativo': True}, {'quadra': 'quadra01', 'valor': True}])

    def test_recusa_do_detector_vira_falha_com_erro(self):
        r, _ = self.aplica({'gatilho': 'xpto'}, resposta=(False, {'erro': "gatilho deve ser 'manual' ou 'ia'"}))
        self.assertFalse(r['ok'])
        self.assertEqual(r['passos'][0]['erro'], "gatilho deve ser 'manual' ou 'ia'")


if __name__ == '__main__':
    unittest.main()
