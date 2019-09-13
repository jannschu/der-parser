extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro_hack::proc_macro_hack;

fn parse_arg(arg: &str) -> (bool, Vec<&str>) {
	use nom::{
		combinator::{recognize, map, opt},
		character::complete::{one_of, char},
		branch::alt,
		bytes::complete::{take_while, tag},
		error::{ParseError, ErrorKind},
		multi::{many0_count, separated_list},
		sequence::{delimited, pair, terminated},
		IResult, exact, call,
	};
	
	fn uint<'a, E: ParseError<&'a str>>(i: &'a str) -> IResult<&'a str, &'a str, E> {
		recognize::<&str, &str, E, _>(
			alt((
				map(char('0'), |_| ""),
				map(pair(one_of("123456789"), many0_count(one_of("0123456789"))), |_| "")
			))
		)(i)
	}
	
	fn ws<'a, E: ParseError<&'a str>>(i: &'a str) -> IResult<&'a str, &'a str, E> {
		take_while(|c| c == ' ')(i)
	}

	fn ws_dot_ws<'a, E: ParseError<&'a str>>(i: &'a str) -> IResult<&'a str, char, E> {
		delimited(ws, char('.'), ws)(i)
	}

	fn root<'a, E: ParseError<&'a str>>(i: &'a str) -> IResult<&'a str, (bool, Vec<&'a str>), E> {
		pair(
			map(opt(terminated(tag("rel "), ws)), |x| x.is_some()),
			separated_list(ws_dot_ws, uint)
		)(i.trim())
	}

	exact!(arg, call!(root::<(&str, ErrorKind)>)).expect("could not parse oid").1
}

#[proc_macro_hack]
pub fn oid(item: TokenStream) -> TokenStream {
	use num_traits::cast::ToPrimitive;

	let arg = item.to_string();
	let (rel, int_strings) = parse_arg(&arg);
	let ints: Vec<num_bigint::BigUint> = int_strings.into_iter()
		.map(|s| s.parse().unwrap())
		.collect();
	
	let mut enc = Vec::new();
	let mut dec = ints.as_slice();
	if !rel {
		if dec.len() < 2 {
			panic!("Need at least two components for non-relative oid");
		}
		if dec[0] > 7u8.into() || (dec[1] > 256u16 - dec[0].clone() * 6u8) {
			panic!("First components are too big");
		}
		enc.push(dec[0].to_u8().unwrap() * 40 + dec[1].to_u8().unwrap());
		dec = &dec[2..];
	}

	for int in dec.into_iter() {
		let mut bytes = int.to_bytes_be();
		if bytes[0] == 0 {
			enc.push(0u8);
			continue;
		}
		let total_bits = (8 - bytes[0].leading_zeros()) as usize + (bytes.len() - 1) * 8;
		let octects_needed = ((total_bits + 6) / 7).max(1);
		enc.resize_with(enc.len() + octects_needed, Default::default);

		let mut pos = enc.len() - 1;
		let mut extra = 0u8;
		let mut extra_size = 0u8;
		bytes.reverse();
		let mut bytes_stored = 0;
		for byte in bytes.into_iter() {
			if extra_size == 7 {
				// there a seven bits in extra
				enc[pos] = extra | (1 << 7);
				bytes_stored += 1;
				pos -= 1;
				extra = 0;
				extra_size = 0;
			}
			// make space for the extra bits
			enc[pos] = (byte << extra_size) | extra | (1 << 7);
			bytes_stored += 1;
			if pos > 0 {
				pos -= 1;
				extra_size += 1;
				extra = byte >> (8 - extra_size);  
			}
		}
		let last = enc.len() - 1;
		if bytes_stored != octects_needed {
			let first = last + 1 - octects_needed;
			enc[first] = extra | (1 << 7);
		}
		enc[last] ^= 1 << 7;
	}

	let mut s = String::with_capacity(2 + 6 * enc.len());
	s.push('[');
	for byte in enc.iter() {
		s.insert_str(s.len(), &format!("0x{:02x}, ", byte));
	}
	s.push(']');

	let code = if rel {
		format!("der_parser::oid::Oid::new_relative(std::borrow::Cow::Borrowed({}.as_ref()))", s)
	} else {
		format!("der_parser::oid::Oid::new(std::borrow::Cow::Borrowed({}.as_ref()))", s)
	};
	code.parse().unwrap()
}