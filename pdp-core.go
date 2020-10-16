package gopdp

import (
	"crypto/rand"
	"math/big"
)

var params PDP_params

type PDPCore struct {
}

/* pdp_tag_block: Client-side function that takes pdp-keys, a generator of QR_N, and block of data, its
 * size and its logical index and creates a pdp tag to be stored with it at the server.  Returns an allocated
 * pdp-tag structure.
 */

func NewPDPCore() *PDPCore {
	return &PDPCore{}
}

func (pdpCore *PDPCore) pdp_tag_block(key *PDP_key, block *string, blocksize *uint64, index uint) *PDP_tag {
	var tag *PDP_tag = nil
	// BN_CTX * ctx = NULL
	var phi *big.Int
	var fdh_hash *big.Int
	var message *big.Int
	var r0 *big.Int
	var r1 *big.Int

	/* Verify keys */
	if key == nil || block == nil || blocksize == nil {
		return nil
	}
	if key.rsa.PublicKey.N == nil {
		return nil
	}
	if key.rsa.PublicKey.E == 0 {
		return nil
	}
	for i := 0; i < 2; i++ {
		if key.rsa.Primes[i] == nil {
			return nil
		}
	}
	if key.g == nil {
		return nil
	}

	/* Allocate memory */
	tag = pdpCore.generate_pdp_tag()

	/* Set the index */
	tag.index = index

	/* Perform the pseudo-random function (prf) Wi = w_v(i) */
	tag.index_prf = pdpCore.generate_prf_w(key, tag.index, tag.index_prf_size)

	/* Peform the full-domain hash function h(Wi) */
	fdh_hash = pdpCore.generate_fdh_h(key, tag.index_prf, *tag.index_prf_size)

	/* Turn the data block into a BIGNUM */
	message, _ = new(big.Int).SetString(*block, int(*blocksize))

	/* Calculate phi */
	r0 = new(big.Int).Sub(key.rsa.Primes[0], new(big.Int).SetInt64(1))
	r1 = new(big.Int).Sub(key.rsa.Primes[0], new(big.Int).SetInt64(1))
	phi = new(big.Int).Mul(fdh_hash, r0)

	/* Reduce the message by modulo phi(N) */
	message = new(big.Int).Mod(message, phi)

	/* r0 = g^m */
	r0 = new(big.Int).Exp(key.g, message, key.rsa.N)
	/* r1 = h(W_i) * g^m */
	r1 = new(big.Int).Mul(fdh_hash, r0)
	/* T_im = (h(W_i) * g^m)^d mod N */
	tag.Tim = new(big.Int).Exp(r1, key.rsa.D, key.rsa.N)

	return tag

}

/* pdp_challenge: A client-side function to generate a random challenge for the server to prove data possession.
 *  Takes pdp-keys, the generator of QR_N and the filesize in blocks.
 *  Returns an allocated pdp-challenge structure.
 *  It's important to note that s must be kept secret from the server.  A server challenge is <c, k1, k2, g_s>.
 */
func (pdpCore *PDPCore) pdp_challenge(key *PDP_key, numfileblocks uint) *PDP_challenge {
	var challenge *PDP_challenge
	var r0 *big.Int

	if key == nil || numfileblocks == 0 {
		return nil
	}

	/* Verify keys */
	if key.rsa.N == nil {
		return nil
	}
	if key.g == nil {
		return nil
	}

	/* Allocate memory */
	challenge = pdpCore.generate_pdp_challenge()

	/* Generate a random secret s of RSA modulus size from Z*N */
	for {
		challenge.s, _ = rand.Int(rand.Reader, key.rsa.N)
		r0 = new(big.Int).GCD(nil, nil, challenge.s, key.rsa.N)
		if r0.Cmp(big.NewInt(1)) == 1 {
			break
		}
	}

	/* Generate the secret base g_s = g^s */
	challenge.g_s = new(big.Int).Exp(key.g, challenge.s, key.rsa.N)

	/* Generate random bytes for symmetric challenge keys */
	challengeK1, _ := GenerateRandomBytes(PRP_KEY_SIZE)
	challenge.k1 = &challengeK1
	challengeK2, _ := GenerateRandomBytes(PRF_KEY_SIZE)
	challenge.k2 = &challengeK2

	/* Challenge the server to test at least 460 blocks (MAGIC_NUM_CHALLENGE_BLOCKS) of the file
	*  (see paper for details on choice of c ) */
	if numfileblocks < MAGIC_NUM_CHALLENGE_BLOCKS {
		challenge.c = numfileblocks
	} else {
		challenge.c = MAGIC_NUM_CHALLENGE_BLOCKS
	}

	challenge.numfileblocks = MAGIC_NUM_CHALLENGE_BLOCKS

	return challenge
}

/* pdp_generate_proof_update: Creates or updates a PDP proof structure.  It should be called
*  for each block of the file challenged.  A called to pdp_generate_proof_final must be called
*  after all calls to update are finished.  It takes in a PDP key, a challenge, the tag of challenged
*  block, a proof, the block of data corresponding to the tag, the block size and challenge index.
*  If the passed in proof structure is NULL, a new proof structure will be allocated.  An updated or
*  new proof structure is returned, or NULL on failure.  Note that this is a server side function
*  so the key and challenge structures should only contain the public components.
 */
func (pdpCore *PDPCore) pdp_generate_proof_update(key *PDP_key, challenge *PDP_challenge, tag *PDP_tag,
	proof *PDP_proof, block *string, blocksize *uint64, j uint) *PDP_proof {

	var coefficient_a *big.Int
	var message *big.Int
	var r0 *big.Int
	var prf_result *string
	var prf_result_size uint64 = 0
	if key == nil || challenge == nil || tag == nil || block == nil || blocksize == nil {
		return nil
	}

	/* Verify keys */
	if key.rsa.N == nil {
		return nil
	}

	/* Allocate memory */
	if proof == nil {
		/* If the proof is NULL, create one */
		proof = pdpCore.generate_pdp_proof()
	}

	/* Data block into a BIGNUM */
	message, _ = new(big.Int).SetString(*block, int(*blocksize))

	if USE_E_PDP == 1 { /* Use E-PDP */

		/* No coefficients to calculate in E-PDP, so T is just product of tags */
		if proof.T.Cmp(big.NewInt(0)) == 1 {
			if tag.Tim == nil {
				return nil
			} else {
				proof.T.Set(tag.Tim)
			}
		} else {
			proof.T = new(big.Int).Mul(proof.T, tag.Tim)
		}

		/* Copy message into r0 for summing */
		if message == nil {
			return nil
		}
		r0.Set(message)
	} else { /* Use S-PDP */

		/* Compute the coefficient for block tag->index, where a_j = f_k2(j) */
		prf_result = pdpCore.generate_prf_f(challenge, j, &prf_result_size)
		if prf_result == nil {
			return nil
		}

		/* Convert prf result to a big number */
		a, err := new(big.Int).SetString(*prf_result, int(prf_result_size))
		coefficient_a = a
		if err {
			return nil
		}

		/* Compute T_im ^ coefficient_a */
		r0 = new(big.Int).Exp(tag.Tim, coefficient_a, key.rsa.N)
		if r0 == nil {
			return nil
		}

		/* Update T, where T = T1m^a1 * ... * Tim^aj */
		if proof.T.Cmp(big.NewInt(0)) == 1 {
			if r0 == nil {
				return nil
			}
			proof.T.Set(r0)
		} else {
			proof.T = new(big.Int).Mul(proof.T, r0)
		}
		/* Compute coefficient_a * message, where message = data block*/
		r0 = new(big.Int).Mul(coefficient_a, message)

	}

	/* Store the sum of (coefficient_a_j * message) in rho_temp. */
	/* If E-PDP, then there's no coefficient */
	if proof.rho_temp.Cmp(big.NewInt(0)) == 0 {
		if r0 == nil {
			return nil
		}
		proof.rho_temp.Set(r0)
	} else {
		proof.rho_temp = new(big.Int).Add(proof.rho_temp, r0)
	}
	/* We do not compute g_s^coefficients*messages or H(g_s^coefficients*messages) until the call to generate_proof_final */

	return proof

}

/* pdp_generate_proof_file: The final step of generating a server-side proof.
*  This shuld only be called once per proof and no more calls to update should
*  be made.  It takes in a PDP proof and PDP challenge structure and returns
*  the final PDP proof or NULL on failure.
 */
func (pdpCore *PDPCore) pdp_generate_proof_final(key *PDP_key, challenge *PDP_challenge, proof *PDP_proof) *PDP_proof {

	if proof == nil {
		return nil
	}
	if key == nil || challenge == nil || proof.rho_temp == nil || proof.rho_temp.Cmp(big.NewInt(0)) == 1 {
		return nil
	}
	if key.rsa.N == nil || challenge.g_s == nil {
		return nil
	}

	/* Compute g_s^ (M1 + M2 + ... + Mc) mod N*/
	proof.rho_temp = new(big.Int).Exp(challenge.g_s, proof.rho_temp, key.rsa.N)
	if proof.rho_temp == nil {
		return nil
	}

	/* Compute H(g_s^(M1 + M2 + ... + Mc)) */
	proof.rho = pdpCore.generate_H(proof.rho_temp, proof.rho_size)
	if proof.rho == nil {
		return nil
	}

	return proof

}

/* pdp_verify_proof: The client-side proof verification function.
 * Takes a user's pdp-key, a challenge, its correspond proof and the file size in blocks.
 * Returns a 1 if verified, 0 otherwise.
 */
func pdp_verify_proof(key *PDP_key, challenge *PDP_challenge, proof *PDP_proof) int {

	var tao *big.Int
	var denom *big.Int
	var coefficient_a *big.Int
	var fdh_hash *big.Int
	var tao_s *big.Int
	var r0 *big.Int
	var index_prf *string
	var index_prf_size uint64 = 0
	var prf_result *string
	var prf_result_size uint64 = 0
	var H_result *string
	var H_result_size uint64 = 0
	var j uint = 0
	var result int = 0
	var indices *uint

	if key == nil || challenge == nil || proof == nil {
		return -1
	}

	/* Verify keys */
	if key.rsa == nil {
		return 0
	}
	if key.rsa.E == 0 {
		return 0
	}
	if key.rsa.N == nil {
		return 0
	}

	/* Make sure we don't have a "sanitized" challenge */
	if challenge.s == nil {
		return 0
	}

	/* Compute tao where tao = T^e */
	tao = new(big.Int).Exp(proof.T, new(big.Int).SetInt64(int64(key.rsa.E)), key.rsa.N)
	if tao == nil {
		return 0
	}

	/* Compute the indices i_j = pi_k1(j); the indices of blocks to sample */
	indices = generate_prp_pi(challenge)
	for j := 0; j < int(challenge.c); j++ {

		/* Perform the pseudo-random function Wi = w_v(i) */
		index_prf = pdpCore.generate_prf_w(key, indices[j], &index_prf_size)
		if index_prf == nil {
			return 0
		}
		/* Calculate the full-domain hash h(W_i) */
		fdh_hash = pdpCore.generate_fdh_h(key, index_prf, index_prf_size)
		if fdh_hash == nil {
			return 0
		}

		if USE_E_PDP == 1 { /* Use E-PDP */
			if fdh_hash == nil {
				return nil
			}
			r0.Set(fdh_hash)
		} else { /* Use S-PDP */
			/* Generate the coefficient for block index a = f_k2(j) */
			prf_result = pdpCore.generate_prf_f(challenge, j, &prf_result_size)
			if prf_result == nil {
				return 0
			}

			/* Convert prf coefficient result to a BIGNUM */
			prf_result = new(big.Int).SetString(prf_result_size, coefficient_a)
			if prf_result == nil {
				return 0
			}

			/* Calculate h(W_i)^a */
			r0 = new(big.Int).Exp(fdh_hash, coefficient_a, key.rsa.N)
			if r0 == nil {
				return 0
			}
		}

		/* Calculate products of h(W_i)^a (no coefficeint a in E-PDP) */
		if denom.Cmp(big.NewInt(0)) == 1 {
			if r0 == nil {
				return 0
			}
			denom.Set(r0)
		} else {
			denom = ModMul(denom, r0, key.rsa.N)
			if denom == nil {
				return 0
			}
		}

	} /* end for */

	/* Calculate tao, where tao = tao/h(W_i)^a mod N */
	/* Inverse h(W_i)^a to create 1/h(W_i)^a */
	denom = new(big.Int).ModInverse(denom, key.rsa.N)
	if denom == nil {
		return 0
	}
	/* tao = tao * 1/h(W_i)^a mod N*/
	tao = new(big.Int).ModMul(tao, denom, key.rsa.N)
	if tao == nil {
		return 0
	}

	/* Calculate tao^s mod N*/
	tao_s = new(big.Int).Exp(tao, challenge.s, key.rsa.N)
	if tao_s == nil {
		return 0
	}

	/* Calculate H(tao^s mod N) */
	H_result = generate_H(tao_s, &(H_result_size))
	if H_result == nil {
		return 0
	}

	/* The final verification step.  Does rho == rho? */
	if H_result == proof.rho {
		result = 1
	}

	return result
}
