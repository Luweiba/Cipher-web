#[derive(Debug)]
pub struct LfsrJk {
    j_state: u32,
    k_state: u32,
    j_state_c: u32,
    k_state_c: u32,
    data_state: u8,
}
impl LfsrJk {
    pub fn new(j_state: u32, k_state: u32, j_state_c: u32, k_state_c: u32, data_state: u8) -> Self {
        Self {
            j_state: 0x12345678 - j_state,
            k_state: 0x87654321 - k_state,
            j_state_c: 0xffffffff - j_state_c,
            k_state_c: 0xffffffff - k_state_c,
            data_state,
        }
    }
    pub fn crypt(&self, data: &mut [u8]) {
        let mut j_state = self.j_state;
        let mut k_state = self.k_state;
        let mut data_state = self.data_state;
        let len = data.len();
        for i in 0..len {
            let j = Self::round(&mut j_state, self.j_state_c);
            let k = Self::round(&mut k_state, self.k_state_c);
            data_state = j ^ (!(j ^ k) & data_state);
            data[i] ^= data_state;
        }
    }
    #[inline]
    fn round(state: &mut u32, state_c: u32) -> u8 {
        let mut output = 0u8;
        for _ in 0..8 {
            let t = *state & state_c;
            let new_out = t.count_ones() % 2;
            let out = (0x80000000 & t) >> 31;
            output = (output << 1) + out as u8;
            *state = (*state << 1) + new_out;
        }
        output
    }
}
