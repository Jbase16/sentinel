import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from core.engine.scanner_engine import ScannerEngine, ResilienceContext, ResourceGuard, ResourceExhaustedError
from core.sentient.diagnosis import ErrorClassifier, ErrorType, Diagnosis

# 1. Test Error Classifier
def test_error_classifier_diagnosis():
    classifier = ErrorClassifier()
    
    # Transient
    d1 = classifier.diagnose(ConnectionResetError("Connection reset by peer"))
    assert d1.type == ErrorType.TRANSIENT
    assert d1.recommendation == "RETRY_WITH_BACKOFF"
    
    # WAF
    d2 = classifier.diagnose(RuntimeError("403 Forbidden: Cloudflare"))
    assert d2.type == ErrorType.WAF_BLOCK
    assert d2.recommendation == "ROTATE_PROXY_OR_COOLDOWN"
    
    # Permanent
    d3 = classifier.diagnose(KeyError("missing key"))
    assert d3.type == ErrorType.PERMANENT
    assert d3.recommendation == "FAIL_TASK"

# 2. Test Resilience Context Retry Logic
@pytest.mark.asyncio
async def test_resilience_retry_transient():
    mock_func = AsyncMock(side_effect=[ConnectionResetError("fail"), "success"])
    
    # Needs a mock engine for init
    mock_engine = MagicMock()
    ctx = ResilienceContext(engine=mock_engine, max_retries=2)
    
    result = await ctx.execute_with_retry(mock_func)
    
    assert result == "success"
    assert mock_func.call_count == 2 # 1 fail, 1 success

@pytest.mark.asyncio
async def test_resilience_fail_permanent():
    mock_func = AsyncMock(side_effect=ValueError("Logic Error"))
    
    mock_engine = MagicMock()
    ctx = ResilienceContext(engine=mock_engine, max_retries=2)
    
    with pytest.raises(ValueError):
        await ctx.execute_with_retry(mock_func)
    
    assert mock_func.call_count == 1 # Fail fast

# 3. Test Stealth Mode Trigger (WAF)
@pytest.mark.asyncio
async def test_resilience_trigger_stealth_mode():
    # Mock function fails with 403
    mock_func = AsyncMock(side_effect=RuntimeError("403 Forbidden"))
    
    mock_engine = MagicMock()
    mock_engine.enable_stealth_mode = MagicMock()
    
    ctx = ResilienceContext(engine=mock_engine, max_retries=1)
    
    try:
        await ctx.execute_with_retry(mock_func)
    except RuntimeError:
        pass
    
    # Should have called enable_stealth_mode
    mock_engine.enable_stealth_mode.assert_called()

# 4. Test Resource Guard Stealth Mode logic
def test_resource_guard_stealth():
    guard = ResourceGuard(max_findings=100)
    assert guard.max_findings == 100
    assert guard._stealth_mode is False
    
    guard.set_stealth_mode(True)
    assert guard._stealth_mode is True
    assert guard.max_findings == 50 # 50% reduction
    
    guard.set_stealth_mode(False)
    assert guard.max_findings == 100 # Restoration
