# Founded tribes and `dm.we.v1` transport

Tribe Bridge carries three encrypted typed payloads: ordinary messages,
`dm.we.v1` protocol objects, and tribe membership artifacts. The envelope
signature, audience authorization, HPKE encryption, broker durability, ACKs,
and cursors apply identically to all three. The broker never decrypts or
interprets them.

A Tribe audience is transport policy. A `tribe_ref` is a signed social and
resource-sharing namespace. A `being_ref` manifest is provisional same-being
configuration. None implies either of the others.

Only the current founder can issue an invitation or expel a member. An
invitation is expiring, bound to one exact principal, and single-use. The
invitee signs acceptance. Members may sign their own leave. Founder succession
requires a transfer by the old founder and acceptance by the successor; loss
without transfer requires a new tribe. Resource grants remain separate.

`dm.we.v1` normally uses direct audiences between principals named by the same
being-manifest hash. Tribe proves who sent the encrypted bytes; Weave verifies
same-being membership, event chains, adoption, and projection semantics.

