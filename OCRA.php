<?php

class OCRA {
	private $suite;
	private $key;
	private $session;
	private $pin;
	private $time = null;

	public function __construct($ocraSuite, $key) {
		$this->suite = $this->_parseSuite($ocraSuite);
		$this->key = $key;
	}

	public function generate($input, $counter = 0) {
		$msg = $this->suite['name']."\0"; // hashed value

		if (isset($this->suite['input']['counter'])) {
			// transform counter in a 64bits big endian int, append to $msg (only works on 64bits servers)
			$msg .= pack('NN', ($counter >> 32) & 0xffffffff, $counter & 0xffffffff);
		}

		// append $input (Q)
		switch($this->suite['input']['format']) {
			case 'n':
				$msg .= str_pad(pack('H*', dechex($input)), 128, "\0", STR_PAD_RIGHT);
				break;
			case 'a':
				if (strlen($input) > 128) $input = substr($input, 0, 128);
				$msg .= str_pad($input, 128, "\0", STR_PAD_RIGHT);
				break;
			case 'h':
				if (strlen($input) > 256) $input = substr($input, 0, 256);
				$msg .= str_pad(pack('H*', $input), 128, "\0", STR_PAD_RIGHT);
				break;
		}

		// check for pin/password (P)
		if (isset($this->suite['input']['pin_hash'])) {
			$msg .= $this->pin;
		}

		// check for session (S)
		if (isset($this->suite['input']['session_len'])) {
			$msg .= str_pad($this->session, $this->suite['input']['session_len'], "\0", STR_PAD_LEFT);
		}

		// check for timestamp (T)
		if (isset($this->suite['input']['ts_resolution'])) {
			if (is_null($this->time)) {
				$time = (int)floor(time() / $this->suite['input']['ts_resolution']);
			} else {
				$time = $this->time;
			}
			// put timestamp as big endian 64 bits int
			$msg .= pack('NN', ($time >> 32) & 0xffffffff, $time & 0xffffffff);
		}

		// compute hash
		$hash = hash_hmac($this->suite['crypto']['algo'], $msg, $this->key, true);

		if (!$this->suite['crypto']['trunc']) return $hash;

		// get offset for the 4 bytes we are going to use
		$offset = ord(substr($hash, -1)) & 0xf;
		// read 32bits big-endian value as offset
		list(,$value) = unpack('N', substr($hash, $offset, 4));
		$value = $value & 0x7fffffff; // make it unsigned
		$length = $this->suite['crypto']['trunc'];
		return str_pad($value % pow(10, $length), $length, '0', STR_PAD_LEFT);
	}

	public static function vsign($data1, $data2) {
		$buffer = "\xe3\x08VSIGN V1\xdf\x71".chr(strlen($data1)).$data1."\xdf\x72".chr(strlen($data2)).$data2;
		return sha1($buffer);
	}

	public function setSession($session) {
		$this->session = pack('H*', $session);
	}

	public function setPin($pin) {
		$this->pin = hash($this->suite['input']['pin_hash'], $pin, true);
	}

	public function setTime($time) {
		if (!isset($this->suite['input']['ts_resolution']))
			throw new Exception('You cannot use setTime() on a OCRA suite without timestamp');
		$this->time = (int)floor($time / $this->suite['input']['ts_resolution']);
	}

	protected function _parseSuite($suite_str) {
		// input is a OCRA suite, for example OCRA-1:HOTP-SHA1-6:QN08
		// See RFC6287 for details
		// http://tools.ietf.org/html/rfc6287#section-6
		// <Algorithm>:<CryptoFunction>:<DataInput>
		$suite = explode(':', $suite_str);
		if (count($suite) != 3) throw new Exception('Invalid OCRA suite provided');

		list($algo, $crypto, $input) = $suite;

		// ocra algo, for now only OCRA-1 exists
		if ($algo != 'OCRA-1') throw new Exception('Unsupported version of OCRA');

		// parse crypto method. Table of possible values exist in RFC on page 7, but we'll be more flexible than that by supporting any hashing method PHP has
		$crypto = explode('-', strtolower($crypto));
		if (count($crypto) != 3) throw new Exception('Invalid OCRA crypto specified');

		if ($crypto[0] != 'hotp') throw new Exception('Invalid OCRA crypto mode specified (only HOTP is accepted)');
		$crypto_algo = $crypto[1];
		$crypto_trunc = (int)$crypto[2];

		if (($crypto_trunc != 0) && (($crypto_trunc < 4) || ($crypto_trunc > 10)))
			throw new \Exception('Invalid hash trunc length specified in OCRA suite');

		if (!in_array($crypto_algo, hash_algos())) throw new Exception('Unsupported crypto algo required');

		// now parse data input
		$input_flags = array();
		$input = explode('-', strtolower($input));
		if ($input[0] == 'c') {
			// counter enabled
			$input_flags['counter'] = true;
			array_shift($input);
		}
		if (strlen($input[0]) != 4) throw new Exception('Badly formatted OCRA suite, QFxx format wrong');
		if ($input[0][0] != 'q') throw new Exception('Badly formatted OCRA suite, QFxx format wrong');
		$input_format = $input[0][1];
		switch($input_format) {
			case 'a': case 'n': case 'h': break;
			default: throw new Exception('Invalid OCRA input format specified in suite');
		}
		$input_length = substr($input[0], 2);
		if (!preg_match('/^[0-9]{2}$/', $input_length)) throw new Exception('Invalid OCRA input length specified');

		$input_flags['format'] = $input_format;
		$input_flags['length'] = (int)$input_length;

		array_shift($input);

		if (($input) && ($input[0][0] == 'p')) {
			// hash
			$pin_hash = substr($input[0], 1);
			if (!in_array($pin_hash, hash_algos())) throw new Exception('Unsupported pin hash specified in OCRA suite');
			$input_flags['pin_hash'] = $pin_hash;
			array_shift($input);
		}

		if (($input) && ($input[0][0] == 's')) {
			if ($input[0] == 's') {
				// default value of 064
				$input_flags['session_len'] = 64;
			} else {
				$input_flags['session_len'] = (int)substr($input[0]);
			}
			array_shift($input);
		}

		if (($input) && ($input[0][0] == 't')) {
			// default value = 1M
			if ($input[0] == 't') {
				$input_flags['ts_resolution'] = 60;
			} else {
				if (!preg_match('/^t([0-9]+)([smh])$/', $input[0], $match))
					throw new Exception('Invalid timestamp speficiation in OCRA suite');
				switch($match[2]) {
					case 's': $input_flags['ts_resolution'] = (int)$match[1]; break;
					case 'm': $input_flags['ts_resolution'] = $match[1]*60; break;
					case 'h': $input_flags['ts_resolution'] = $match[1]*3600; break;
				}
			}
		}

		return array(
			'name' => $suite_str,
			'algo' => $algo, // OCRA-1
			'crypto' => array('algo' => $crypto_algo, 'trunc' => $crypto_trunc),
			'input' => $input_flags,
		);
	}
}

