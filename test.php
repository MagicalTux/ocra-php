<?php

include('OCRA.php');

date_default_timezone_set('GMT'); // avoid PHP warnings

class Test {
	const KEY_20 = "3132333435363738393031323334353637383930";
	const KEY_32 = "3132333435363738393031323334353637383930313233343536373839303132";
	const KEY_64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";
	const PIN_1234_HASH = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";

	public static function assertEq($v1, $v2) {
		$bt = debug_backtrace();
		$line = $bt[0]['line'];
		if ($v1 != $v2) {
			echo "Test failed at line $line, got $v2 instead of $v1\n";
		} else {
			echo "Test passed at line $line ...\r";
		}
	}

	public static function run() {
		echo "Testing suite OCRA-1:HOTP-SHA1-6:QN08 ...\n";
		$suite = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', pack('H*', self::KEY_20));
		self::assertEq('237653', $suite->generate('00000000'));
		self::assertEq('243178', $suite->generate('11111111'));
		self::assertEq('653583', $suite->generate('22222222'));
		self::assertEq('740991', $suite->generate('33333333'));
		self::assertEq('608993', $suite->generate('44444444'));
		self::assertEq('388898', $suite->generate('55555555'));
		self::assertEq('816933', $suite->generate('66666666'));
		self::assertEq('224598', $suite->generate('77777777'));
		self::assertEq('750600', $suite->generate('88888888'));
		self::assertEq('294470', $suite->generate('99999999'));

		echo "Testing suite OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1 ...\n";
		$suite = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', pack('H*', self::KEY_32));
		$suite->setPin('1234');
		self::assertEq('65347737', $suite->generate('12345678', 0));
		self::assertEq('86775851', $suite->generate('12345678', 1));
		self::assertEq('78192410', $suite->generate('12345678', 2));
		self::assertEq('71565254', $suite->generate('12345678', 3));
		self::assertEq('10104329', $suite->generate('12345678', 4));
		self::assertEq('65983500', $suite->generate('12345678', 5));
		self::assertEq('70069104', $suite->generate('12345678', 6));
		self::assertEq('91771096', $suite->generate('12345678', 7));
		self::assertEq('75011558', $suite->generate('12345678', 8));
		self::assertEq('08522129', $suite->generate('12345678', 9));

		echo "Testing suite OCRA-1:HOTP-SHA256-8:QN08-PSHA1 ...\n";
		$suite = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', pack('H*', self::KEY_32));
		$suite->setPin('1234');
		self::assertEq('83238735', $suite->generate('00000000'));
		self::assertEq('01501458', $suite->generate('11111111'));
		self::assertEq('17957585', $suite->generate('22222222'));
		self::assertEq('86776967', $suite->generate('33333333'));
		self::assertEq('86807031', $suite->generate('44444444'));

		echo "Testing suite OCRA-1:HOTP-SHA512-8:C-QN08 ...\n";
		$suite = new OCRA('OCRA-1:HOTP-SHA512-8:C-QN08', pack('H*', self::KEY_64));
		self::assertEq('07016083', $suite->generate('00000000', 0));
		self::assertEq('63947962', $suite->generate('11111111', 1));
		self::assertEq('70123924', $suite->generate('22222222', 2));
		self::assertEq('25341727', $suite->generate('33333333', 3));
		self::assertEq('33203315', $suite->generate('44444444', 4));
		self::assertEq('34205738', $suite->generate('55555555', 5));
		self::assertEq('44343969', $suite->generate('66666666', 6));
		self::assertEq('51946085', $suite->generate('77777777', 7));
		self::assertEq('20403879', $suite->generate('88888888', 8));
		self::assertEq('31409299', $suite->generate('99999999', 9));

		echo "Testing suite OCRA-1:HOTP-SHA512-8:QN08-T1M ...\n";
		$suite = new OCRA('OCRA-1:HOTP-SHA512-8:QN08-T1M', pack('H*', self::KEY_64));
		$suite->setTime(strtotime('Mar 25 2008, 12:06:30 GMT'));
		self::assertEq('95209754', $suite->generate('00000000'));
		self::assertEq('55907591', $suite->generate('11111111'));
		self::assertEq('22048402', $suite->generate('22222222'));
		self::assertEq('24218844', $suite->generate('33333333'));
		self::assertEq('36209546', $suite->generate('44444444'));

		echo "Testing suite OCRA-1:HOTP-SHA256-8:QA08 ...\n";
		$suite = new OCRA('OCRA-1:HOTP-SHA256-8:QA08', pack('H*', self::KEY_32));
		self::assertEq('28247970', $suite->generate('CLI22220SRV11110'));
		self::assertEq('01984843', $suite->generate('CLI22221SRV11111'));
		self::assertEq('65387857', $suite->generate('CLI22222SRV11112'));
		self::assertEq('03351211', $suite->generate('CLI22223SRV11113'));
		self::assertEq('83412541', $suite->generate('CLI22224SRV11114'));

		echo "End of tests!                       \n";
	}
}

Test::run();

