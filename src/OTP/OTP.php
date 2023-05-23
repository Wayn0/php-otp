<?php
/**
 * OTP Class, copied from https://github.com/lelag/otphp 
 *
 * @package     wayne-oliver/simple-otp
 * @author      Wayne Oliver <info@wayneoliver.co.za>
 * @license     BSD
 ********************************** 80 Columns *********************************
 **/

namespace OTP;

class OTP
{
    public $skey;  //BASE32 encoded secret key
    public $algo;  //hashing algorithm
    public $plen;  //One time pin length

    /**
     * Constructor for the OTP class
     * @param string $key the secret key
     * @param array $option, options array can contain the
     * following keys :
     *   @param integer plen : the length of the one time pin
     *   @param string  algo : the algorithm used for the hmac hash function
     *
     * @return new OTP class.
     */
    public function __construct($secret, $options = Array())
    {
        $this->plen = isset($options['plen']) ? $options['plen'] : 6;
        $this->algo = isset($options['algo']) ? $options['algo'] : 'sha1';
        $this->skey = $secret;
    }


    /**
     * Generate a one-time password
     *
     * @param integer $input : number used to seed the hmac hash function.
     *
     * @return integer the one-time password
     */
    public function get_otp($input)
    {
        $hash = hash_hmac($this->algo, $this->int_to_byte_string($input), $this->decode_key());
        foreach(str_split($hash, 2) as $hex) {
            $hmac[] = hexdec($hex);
        }
        $offset = $hmac[19] & 0xf;
        $code = ($hmac[$offset+0] & 0x7F) << 24 |
            ($hmac[$offset + 1] & 0xFF) << 16 |
            ($hmac[$offset + 2] & 0xFF) << 8 |
            ($hmac[$offset + 3] & 0xFF);
        return $code % pow(10, $this->plen);
    }

    /**
     * Returns the binary value of the base32 encoded secret skey
     *
     * @return binary secret key
     */
    public function decode_key() {
        return \Base32\Base32::decode($this->skey);
    }

    /**
     * Turns an integer in a OATH bytestring
     * @param integer $int
     *
     * @return string bytestring
     */
    public function int_to_byte_string($int) {
        $result = Array();
        while($int != 0) {
            $result[] = chr($int & 0xFF);
            $int >>= 8;
        }
        return str_pad(join(array_reverse($result)), 8, "\000", STR_PAD_LEFT);
    }
}
