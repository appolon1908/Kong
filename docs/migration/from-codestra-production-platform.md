# Repository extraction provenance

- source repository: `appolon1908/codestra-production-platform`
- protected source SHA: `f3a16308194378a7b1580e04943dc98d64619077`
- route hardening PR: `#130`
- route authority SHA: `b340023f5e74e1f9154fc97590c9b6a48caa8b99`
- target repository: `appolon1908/Kong`

This extraction changes source ownership only. It does not mutate live Kong,
PostgreSQL, Caddy, DNS, firewall, containers, or traffic. Historical commits remain
in the platform repository and are referenced rather than falsely rewritten as
native history in the new repository.
