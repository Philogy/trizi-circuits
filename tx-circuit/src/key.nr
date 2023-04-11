use dep::std;

fn deriv_pubkey(privkey: Field) -> Field {
  std::hash::pedersen([privkey])[0]
}
