import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from simulacra.core import SimulacraEngine

class TestSimulacra(unittest.TestCase):
    def test_order(self):
        e=SimulacraEngine()
        r=e.analyze_order(4)
        self.assertEqual(r["name"],"Pure Simulacrum")
    def test_classify(self):
        e=SimulacraEngine()
        r=e.classify_media("AI generated deepfake video")
        self.assertEqual(r["order"],4)
    def test_hyperreality(self):
        e=SimulacraEngine()
        r=e.hyperreality_index({"media_saturation":True,"social_media_presence":True,"virtual_experiences":True,"ai_content":True})
        self.assertEqual(r["phase"],"Hyperreal")

if __name__=="__main__": unittest.main()
