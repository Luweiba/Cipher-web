//！ RC4加密算法实现

#[derive(Debug)]
pub struct Rc4 {
    s: [u32; 256],
    key: Vec<u8>,
}

impl Rc4 {
    pub fn new(key: Vec<u8>) -> Self {
        let mut key = key;
        if key.len() == 0 {
            key = vec![1, 2, 3, 4, 5];
        }
        let mut rc4 = Self {
            s: [0u32; 256],
            key,
        };
        rc4.init();
        rc4
    }
    pub fn init(&mut self) {
        let mut k = vec![0u32; 256];
        for i in 0..256 {
            self.s[i] = i as u32;
            k[i] = self.key[i % self.key.len()] as u32;
        }
        let mut j = 0;
        for i in 0..256 {
            j = (j + self.s[i] + k[i]) % 256;
            let tmp = self.s[i];
            self.s[i] = self.s[j as usize];
            self.s[j as usize] = tmp;
        }
    }
    pub fn crypt(&mut self, data: &mut [u8]) {
        let mut i = 0;
        let mut j = 0;
        let mut t = 0;
        let mut s = self.s.clone();
        for k in 0..data.len() {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            let tmp = s[i];
            s[i] = s[j as usize];
            s[j as usize] = tmp;
            t = (s[i] + s[j as usize]) % 256;
            data[k] ^= s[t as usize] as u8;
        }
    }
}
