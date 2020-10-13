package gopdp

import (
	RSA "crypto/rsa"
	"math/big"
	"os"
)

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

type PDP_generator big.Rat

type PDP_key struct {
	rsa *RSA.PrivateKey
	v   *string
	g   *PDP_generator
}

type PDP_tag struct {
	Tim            *big.Rat
	index          uint
	index_prf      *uint
	index_prf_size *uint64
}

type PDP_challenge struct {
	c             uint
	numfileblocks uint
	g_s           *big.Rat
	s             *big.Rat
	k1            *string
	k2            *string
}

type PDP_proof struct {
	T        *big.Rat
	rho_temp *big.Rat
	rho      *string
	rho_size uint64
}

type PDP interface {
	/* PDP file operations in pdp-file.go */
	pdp_tag_file(filepath *string, filePathLen *uint64, tagFilepath *string, tagFilepathLen *uint64)

	pdp_challenge_file(numfileblocks uint) *PDP_challenge

	/* NOTE: It's important that challenge->s must be kept secret from the server.  A server challenge is <c, k1, k2, g_s>.
	 * Also, the key structures should only contain the public components.  See: pdp_get_pubkey() */
	pdp_prove_file(filepath *string, filePathLen uint64, tagFilepath *string, tagFilepathLen *uint64, challenge *PDP_challenge, key *PDP_key) *PDP_proof

	pdp_verify_file(challenge *PDP_challenge, proof *PDP_proof) int

	/* This function is really used more testing as it does challenging, proof generation and verification */
	pdp_challenge_and_verify_file(filepath *string, filePathLen uint64, tagFilepath *string, tagFilepathLen *uint64) int
	read_pdp_tag(tagfile *os.File, index uint) *PDP_tag

	/* PDP core primatives in pdp-core.c*/

	pdp_tag_block(key *PDP_key, block *string, blocksize uint64,
		index uint) PDP_tag

	pdp_challenge(key *PDP_key, numfileblocks uint64) PDP_challenge

	pdp_generate_proof_update(key *PDP_key, challenge *PDP_challenge, tag *PDP_tag,
		proof *PDP_proof, block *string, blocksize uint64, j uint) *PDP_proof

	pdp_generate_proof_final(key *PDP_key, challenge *PDP_challenge, proof *PDP_proof) *PDP_proof

	pdp_verify_proof(key *PDP_key, challenge *PDP_challenge, proof *PDP_proof) int

	/* PDP keying functions pdp-key.c */

	pdp_create_new_keypair() *PDP_key

	pdp_get_keypair() *PDP_key

	pdp_get_pubkey() *PDP_key

	generate_pdp_key() *PDP_key
	destroy_pdp_key(key *PDP_key)

	/* Helper functions in pdp-misc.c */

	sfree(ptr *interface{}, size uint64)

	sanitize_pdp_challenge(challenge *PDP_challenge) *PDP_challenge

	generate_prp_pi(challenge *PDP_challenge) *uint
	generate_H(input *big.Rat, H_result_size *uint64) *string
	generate_prf_f(challenge *PDP_challenge, j uint, prf_result_size *uint64) *string
	generate_prf_w(key *PDP_key, index uint, prf_result_size *uint64) *string
	generate_fdh_h(key *PDP_key, index_prf *string, index_prf_size uint64) *big.Rat

	pick_pdp_generator(n *big.Rat) *PDP_generator
	destroy_pdp_generator(g *PDP_generator)

	generate_pdp_tag() *PDP_tag
	destroy_pdp_tag(tag *PDP_tag)

	generate_pdp_challenge() *PDP_challenge
	destroy_pdp_challenge(challenge *PDP_challenge)

	generate_pdp_proof() *PDP_proof
	destroy_pdp_proof(proof *PDP_proof)
}
