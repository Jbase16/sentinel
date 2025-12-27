
import unittest
from typing import Protocol

# Phase 1
from core.aegis.doppelganger import DoppelgangerService, PersonaManager, SAFE_MODE as DOPPEL_SAFE
from core.thanatos.economic_recon import EconomicReconService, ScraperEngine, SAFE_MODE as ECON_SAFE

# Phase 2
from core.thanatos.hallucinator import HallucinatorService, AxiomSynthesizer, SAFE_MODE as HAL_SAFE
from core.thanatos.anomaly_client import AnomalyClientService, RawSocketHandler, SAFE_MODE as ANOM_SAFE
from core.thanatos.isomorphism import IsomorphismService, GraphMatcher, SAFE_MODE as ISO_SAFE
from core.thanatos.karma_wallet import KarmaWalletService, KarmaPolicy, SAFE_MODE as KARMA_SAFE

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
        hal = HallucinatorService()
        self.assertTrue(hasattr(hal, "hallucinate_batch"))
        
        # Anomaly Client
        anom = AnomalyClientService()
        self.assertTrue(hasattr(anom, "transmit_heretic"))
        
        # Isomorphism
        iso = IsomorphismService()
        self.assertTrue(hasattr(iso, "analyze_target"))
        
        # Karma
        karma = KarmaWalletService()
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
        mgr = ThanatosManager()
        self.assertTrue(hasattr(mgr, "get_hallucinator"))
        self.assertTrue(hasattr(mgr, "verify_reality"))

if __name__ == "__main__":
    unittest.main()
