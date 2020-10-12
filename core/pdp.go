package gopdp

const (
	PRF_KEY_SIZE = 20
	PRP_KEY_SIZE = 16
	RSA_KEY_SIZE = 1024

	PDP_BLOCKSIZE = 4096

	/* 460 blocks gives you 99% chance of detecting an error, 300 blocks gives you 95% chance*/
	MAGIC_NUM_CHALLENGE_BLOCKS = 460
)

type PDP_params struct {
	prf_key_size uint
	prp_key_size uint
	rsa_key_size uint
	rsa_e        uint

	block_size    uint
	num_challenge uint
}
