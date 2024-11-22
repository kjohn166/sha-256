#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_assignments)]

use macroquad::prelude::*;

#[macroquad::main("SHA-256")]
// Just some gui graphics stuff, not SHA-256 related
async fn main () {

    let mut input = String::new();

    let rectangle_width = 400.0;
    let rectangle_height = 35.0;
    let rectangle_thickness = 6.0;
    let available_rect_width = rectangle_width - 10.0;

    let rect_x = screen_width() / 2.0 - rectangle_width / 2.0;
    let rect_y = screen_height() / 1.5;

    let mut text_cursor_pos = 0.0;
    let text_offset_x = 2.0;
    let text_offset_y = rectangle_height / 2.0 + 10.0;

    
    let mut hash: String = "".to_string();
    let mut prev_str: String = "".to_string();

    let title_str = "SHA-256 hash function, type to enter message".to_string();
    let title_width = measure_text(&title_str, None, 30, 1.0).width;

    loop {
        clear_background(BLACK);


        draw_rectangle_lines(screen_width() / 2.0 - rectangle_width / 2.0, screen_height() / 1.5, rectangle_width, rectangle_height, rectangle_thickness, WHITE);
        draw_text(&title_str, screen_width() / 2.0 - title_width / 2.0, 50.0, 30.0, WHITE);

        let text_width = measure_text(&input, None, 30, 1.0).width;
        if text_width > available_rect_width {
            text_cursor_pos = text_width - available_rect_width;
        } else {
            text_cursor_pos = 0.0;
        }

        draw_text(&input, rect_x + text_offset_x - text_cursor_pos, rect_y + text_offset_y, 30.0, WHITE);
        


        if let Some(c) = get_char_pressed() {
            if c.is_ascii() && !c.is_control() {
                input.push(c);
            }
        }

        if is_key_pressed(KeyCode::Backspace) && !input.is_empty() {
            input.pop();
        }
        
        if is_key_pressed(KeyCode::Enter) {
            hash = Sha256(input.clone());
            prev_str = format!("input message: {:?}", input.clone()).to_string();
            input = "".to_string();
        }
        
        let hash_width = measure_text(&hash, None, 20, 1.0).width;
        let prev_str_width = measure_text(&prev_str, None, 20, 1.0).width;
        draw_text(&prev_str, screen_width() /2.0 - prev_str_width / 2.0, screen_height() / 2.0 - 15.0, 20.0, WHITE);
        draw_text(&hash, screen_width() / 2.0 - hash_width / 2.0, screen_height() / 2.0, 20.0, WHITE);

        next_frame().await
    }
}



// hash values
// these are the first 32 bits of the fractional parts of the sqaure roots of the first 8 primes
const HASH_VAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

// array of round constants
// these are the first 32 bits of the fractional parts of the cube roots of the first 64 primes
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

pub fn Sha256(mut message: String) -> String { 
    
    // read message from user
    
    //io::stdin().read_line(&mut message).expect("error: unable to read input");
    message = message.trim().to_string();
    
    //convert message to bytes
    let message_bytes = message.as_bytes();
    
    //print message binary representaion and count number of bits
    let mut i: u64 = 0;
    print!("\nmsg in binary: ");
    for byte in message_bytes {
        print!("{:08b}", byte);
        i += 1;
    }
    print!("\n");
    
    //number of total bits in message = number of bytes * 8
    let L: u64 = i * 8;

    // preprocessing string to add padding according to SHA-256 description
    let paddedMessage = addPadding(message_bytes, L);

    // initalize mutable hash values provided by SHA-256 outline
    // these are the first 32 bits of the fractional parts of the sqaure roots of the first 8 primes
    let mut h0 = HASH_VAL[0];
    let mut h1 = HASH_VAL[1];
    let mut h2 = HASH_VAL[2];
    let mut h3 = HASH_VAL[3];
    let mut h4 = HASH_VAL[4];
    let mut h5 = HASH_VAL[5];
    let mut h6 = HASH_VAL[6];
    let mut h7 = HASH_VAL[7];

    // process each chunk of 512-bits, chunking into partitions of 64 bytes (64 bytes = 512 bits)
    for chunk in paddedMessage.chunks(64) {

        // declare the message schedule array
        let mut w: [u32; 64] = [0; 64];

        // extract the first 16 32-bit words from the padded message
        for i in 0..16 {

            // here we extract 4 bytes at time from the 64 byte chunk until we get them all
            w[i] = u32::from_be_bytes(chunk[4*i..4*i+4].try_into().unwrap());
        }
        
        // extend the first 16 words into the rest of the 48 words of the message schedule array (w)
        // what we do here is take the original 512 bit input, treat is a 16 32-bit words and turn
        // that into 64 32-bit words
        for i in 16..64 {
            let s0 = (w[i-15].rotate_right(7)) ^ (w[i-15].rotate_right(18)) ^ (w[i-15] >> 3);
            let s1 = (w[i-2].rotate_right(17)) ^ (w[i-2].rotate_right(19)) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        //initialize working variables to current hash values
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;
        
         // this is the main loop for the SHA-256 compression function, goes for 64 rounds
        for i in 0..64 {
            let S1 = (e.rotate_right(6)) ^ (e.rotate_right(11)) ^ (e.rotate_right(25));
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(S1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let S0 = (a.rotate_right(2)) ^ (a.rotate_right(13)) ^ (a.rotate_right(22));
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = S0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        //add compressed chunk to current hash value
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);

    }
    
    // print the hash by concatenating all our new hash values (prints big-endian)
    println!("\nHash: 0x{:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}\n", h0, h1, h2, h3, h4, h5, h6, h7);

    // just formating the hash for the return value to print to gui screen
    let hash = format!("Hash: 0x{:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}", h0, h1, h2, h3, h4, h5, h6, h7);
    hash.to_string();

    hash
}

//add padding to the message, appending by 1 byte at a time
pub fn addPadding(message: &[u8], L: u64) -> Vec<u8> {

        //convert message to expandable vector
        let mut paddedMessage = message.to_vec();
        
        //append a 1 to end of message before padding
        paddedMessage.push(0x80);
        
        // we want a multiple of 448 bits since we will have to add on a 64-bit big-endian integer
        // at the end of the 512 bit block we need for processing
        while (paddedMessage.len() * 8) % 512 != 448 {
            //append a 0 to end of message
            paddedMessage.push(0x00);
        }

        //convert L to 64-bit big-endian and append to padded message
        paddedMessage.extend_from_slice(&L.to_be_bytes());
        
        //return value
        paddedMessage
}

