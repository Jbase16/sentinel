
import unittest
from typing import Protocol

# Phase 1
from core.sentient.doppelganger import DoppelgangerService, PersonaManager, SAFE_MODE as DOPPEL_SAFE
from core.aegis.economic_recon import EconomicReconService, ScraperEngine, SAFE_MODE as ECON_SAFE

# Phase 2
from core.thanatos.axiom_synthesizer import MutationEngine, SAFE_MODE as HAL_SAFE
from core.thanatos.anomaly_client import AnomalyClientService, RawSocketHandler, SAFE_MODE as ANOM_SAFE
from core.thanatos.isomorphism_engine import IsomorphismService, GraphMatcher, SAFE_MODE as ISO_SAFE
from core.thanatos.karma_model import KarmaModelService, KarmaPolicy, SAFE_MODE as KARMA_SAFE

# Phase 3
from core.thanatos.meta_observer import ObserverService, EntropyMonitor, SAFE_MODE as OBS_SAFE
from core.thanatos.truth_discriminator import TruthService, DeceptionScanner, SAFE_MODE as TRUTH_SAFE
from core.thanatos.manager import ThanatosManager, SAFE_MODE as MGR_SAFE

class TestThanatosStructure(unittest.TestCase):

    def test_thanatos_safety_locks(self):
        """Verify all modules default to SAFE_MODE = True."""
        self.assertTrue(DOPPEL_SAFE)
        self.assertTrue(ECON_SAFE)
        self.assertTrue(HAL_SAFE)
        self.assertTrue(ANOM_SAFE)
        self.assertTrue(ISO_SAFE)
        self.assertTrue(KARMA_SAFE)
        self.assertTrue(OBS_SAFE)
        self.assertTrue(TRUTH_SAFE)
        self.assertTrue(MGR_SAFE)

    def test_phase1_structure(self):
        """Verify AEGIS/Foundation structure."""
        svc = DoppelgangerService()
        self.assertTrue(hasattr(svc, "create_session"))
        self.assertTrue(hasattr(svc, "replay"))
        
        econ = EconomicReconService()
        self.assertTrue(hasattr(econ, "build_financial_map"))

    def test_phase2_structure(self):
        """Verify Architecture structure."""
        # Hallucinator
        # Mutation Engine (formerly Hallucinator)
        hal = MutationEngine()
        self.assertTrue(hasattr(hal, "synthesize"))
        
        # Anomaly Client
        anom = AnomalyClientService()
        self.assertTrue(hasattr(anom, "transmit_heretic"))
        
        # Isomorphism
        iso = IsomorphismService()
        self.assertTrue(hasattr(iso, "analyze_target"))
        
        # Karma
        karma = KarmaModelService()
        self.assertTrue(hasattr(karma, "authorize_action"))

    def test_phase3_structure(self):
        """Verify Synthesis structure."""
        # Observer
        obs = ObserverService()
        self.assertTrue(hasattr(obs, "check_state"))
        
        # Truth
        truth = TruthService()
        self.assertTrue(hasattr(truth, "analyze_session"))
        
        # Manager
        class MockAegis:
             pass
        class MockEvents:
             pass
             
        mgr = ThanatosManager(aegis=MockAegis(), events=MockEvents())
        self.assertTrue(hasattr(mgr, "generate_for_high_value_targets"))
        self.assertTrue(hasattr(mgr, "configure_scope"))

if __name__ == "__main__":
    unittest.main()
