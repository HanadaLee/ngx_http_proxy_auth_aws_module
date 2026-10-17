# S3 canonical request fixtures

`s3-canonical.jsonl` contains 731 request targets and the canonical path/query
returned by AWS S3 in `ap-northeast-1` during direct TLS/HTTP/1.1 tests on
2026-10-17. Expected canonical strings are recorded observations, not calculated
by the implementation under test. The private test prefix was replaced by a
same-length neutral prefix; bucket names, credentials, signatures, dates, and
request identifiers are not included.

The source run had 880 cases. Of these, 731 returned a Canonical Request and
149 were rejected before returning one. `s3-invalid-paths.jsonl` retains 148
malformed-escape, NUL, and invalid-UTF-8 paths as signing-rejection cases. The
remaining case traversed above the object-key root; it is omitted because that
is an S3 object-key restriction rather than a canonicalization rule. S3's
rejection status is not used as the expected local HTTP status: an invalid
upstream path causes this module to fail signing with HTTP 500.

Recorded coverage includes:

- All 256 percent-encoded byte values in paths and query values (including
  rejection cases), printable raw ASCII paths, and representative UTF-8 bounds.
- Literal plus versus encoded plus, spaces, reserved characters, uppercase and
  lowercase escapes, nested percent encoding, and 100 mixed-encoding paths.
- Repeated slashes, dot segments, Unicode normalization distinctions, and
  1023/1024/1025-byte object keys in literal and percent-encoded form.
- Duplicate parameters, empty names/values, encoded names, multiple equals
  signs, malformed escapes, and invalid-UTF-8 query replacement.

`canonical_uri.t` also adds synthetic regressions for all 256 query-name byte
values, root/empty queries, deeper escaping, multi-byte length boundaries,
larger duplicate-parameter sets, and HEAD/OPTIONS. These are labeled in the test
and are not presented as additional live AWS observations.

Each accepted target is sent to a loopback echo upstream through a variable
`proxy_pass`. The client carries an unrelated query string, so the test catches
accidental fallback to client arguments. Assertions independently check the
unaltered upstream request line and an HMAC calculated with Perl Digest::SHA
from the expected canonical strings. Additional cases cover unchanged original
client targets and URI rewrites. No successful AWS response is required to run
the suite; transient live-service failures are not retried or encoded into the
expected behavior.
