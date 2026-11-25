"""ZeroTrace engine modules package."""

from zerotrace.engine.modules.headers import SecurityHeadersModule
from zerotrace.engine.modules.ssl_tls import SSLTLSModule
from zerotrace.engine.modules.cookies import CookieSecurityModule
from zerotrace.engine.modules.recon import ReconModule
from zerotrace.engine.modules.info_disclosure import InfoDisclosureModule
from zerotrace.engine.modules.session_security import SessionSecurityModule
from zerotrace.engine.modules.insecure_design import InsecureDesignModule

# Register all modules here so the orchestrator can discover them
MODULE_REGISTRY = [
    SecurityHeadersModule,
    SSLTLSModule,
    CookieSecurityModule,
    ReconModule,
    InfoDisclosureModule,
    SessionSecurityModule,
    InsecureDesignModule,  # A04: Insecure Design
]
