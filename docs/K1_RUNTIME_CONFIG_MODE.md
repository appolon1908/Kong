# K1 Runtime / configuration mode authority

Production authority is **Hybrid mode**. Traditional mode is fallback-only and requires explicit approval. Standalone DB-less production is forbidden.

Declarative configuration is validation/source-generation authority; it is not independent runtime-apply authority. The Admin API is never public: disabled on proxy/data planes and loopback-only on the control plane. Hybrid clustering uses private-PKI mTLS on ports 8005/8006.

Runtime apply remains unauthorized until its separate implementation/certification gate passes.
