# OCRA implementation in PHP

Based on RFC 6287

Because the only OCRA implementation I could find was very poorly written,
and based on the very poorly written sample code included in the RFC, I wrote
my own implementation.

## Usage

This library is made to be easy to use, and to include the fact that you will
often need to generate multiple values for a same suite/key (for example when
checking if the client's device hasn't skipped values in the counter due to
codes generated and dropped). The suite is parsed only when the object is
constructed, which helps avoiding unneeded work on subsequent generations.

	<?php
	require_once('OCRA.php');
	$suite = new OCRA('OCRA-1:HOTP-SHA1-6:C-QN08', $bin_key); // key needs to be binary
	$res = $suite->generate($challenge, $counter);
	echo $res;

## Warnings

Note that this implementation will support suites that are not allowed by the
standard, as it will accept any hash algo supported by PHP's hash extension.
For example a suite such as OCRA-1:HOTP-RIPEMD320-6:QN08 would work just fine
with this implementation.

On the other hand, the suite parser is more strict than the one in the
reference implementation found in the RFC, and follows the RFC more closely.
It is sad to say that the implementation provided as reference is actually
poorly written, going as far as manipulating binary data as hexadecimal
strings before actually generating an output.

The RFC is also very vague on the encoding of the question. While the suite
specifies the format (numeric, hexadecimal or alphanumeric), little is said
on the actual encoding, and no test vectors are provided for hexadecimal keys.

