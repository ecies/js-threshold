# @ecies/threshold

K-of-N threshold envelope encryption built on [eciesjs](https://github.com/ecies/js).

A random data key is split with Shamir's secret sharing, and each share is encrypted with ECIES to one recipient. Any K recipients together can recover the data key and decrypt; fewer than K cannot.

This is threshold access control, not threshold decryption: the data key is reassembled wherever the shares are combined.

## Status

Under development and not yet published. The design is tracked in [#1](https://github.com/ecies/js-threshold/issues/1), and `SPEC.md` will specify the envelope format.

## License

[MIT](./LICENSE)
