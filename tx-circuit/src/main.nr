use dep::std;
mod key;
mod utils;

global MAX_IN_COUNT: Field = 4;

fn main(
  amount_delta: pub Field,

  in_count: u8,
  in_commits: pub [Field; MAX_IN_COUNT],
  in_amounts: [Field; MAX_IN_COUNT],
  in_privkeys: [Field; MAX_IN_COUNT],
  nullifiers: pub [Field; MAX_IN_COUNT],

  out_count: u8,
  out_commits: pub [Field; MAX_IN_COUNT],
  out_amounts: [Field; MAX_IN_COUNT],
  out_pubkeys: [Field; MAX_IN_COUNT]
) {
  constrain in_count <= MAX_IN_COUNT as u8;
  constrain out_count <= MAX_IN_COUNT as u8;

  // Range check in amounts to avoid overflows.
  for i in 0..MAX_IN_COUNT {
    utils::range_check128(in_amounts[i]);
  }

  // Range check out amounts to avoid overflows.
  for i in 0..MAX_IN_COUNT {
    utils::range_check128(out_amounts[i]);
  }

  // Verifies Input Commits, Knowledge of Privkey and Nullifier construction.
  // Also sums total input value.
  let mut total_in: Field = 0;
  for i in 0..MAX_IN_COUNT {
    if i as u8 < in_count {
      let pubkey: Field = key::deriv_pubkey(in_privkeys[i]);
      constrain std::hash::pedersen([in_amounts[i], pubkey])[0] == in_commits[i];
      constrain std::hash::pedersen([in_commits[i], in_privkeys[i]])[0] == nullifiers[i];
      total_in += in_amounts[i];
    } else {
      // Ensure that decoy nullifiers are constructed differently to mitigate collisions.
      constrain std::hash::pedersen([in_privkeys[i]])[0] == nullifiers[i];
    }
  }

  // Verifies Output Commits.
  let mut total_out: Field = 0;
  for i in 0..MAX_IN_COUNT {
    if i as u8 < out_count {
      constrain std::hash::pedersen([out_amounts[i], out_pubkeys[i]])[0] == out_commits[i];
      total_out += out_amounts[i];
    } else {
      // Ensure that decoy outputs are encoded differently so that it's not possible to spend.
      constrain std::hash::pedersen([out_pubkeys[i]])[0] == out_commits[i];
    }
  }

  /// @dev `amount_delta` not constrained to be within "safe" range to allow for representing
  /// negative values. Safety which will **need** to be done out-of-circuit.
  constrain total_in == total_out + amount_delta;
}
