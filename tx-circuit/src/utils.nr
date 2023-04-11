fn range_check128(x: Field) {
  let bits: [u1] = x.to_le_bits(253);
  for i in 128..253 {
    constrain bits[i] == 0;
  }
}
