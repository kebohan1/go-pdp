package pdp

import (
	"github.com/kebohan1/go-pdp/pdp-interface"
)

var params PDP_params

/* pdp_tag_block: Client-side function that takes pdp-keys, a generator of QR_N, and block of data, its
 * size and its logical index and creates a pdp tag to be stored with it at the server.  Returns an allocated 
 * pdp-tag structure.
 */

pdp_tag_block(key *PDP_key, block *string, blocksize *uint64, index uint) {
	
}