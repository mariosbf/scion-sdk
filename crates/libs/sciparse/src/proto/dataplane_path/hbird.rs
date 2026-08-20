// Copyright 2026 Mario San-Bento Furtado
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hummingbird SCION path support.
//!
//! Hummingbird extends the standard SCION path with flyover reservations and a
//! millisecond-precision timestamp in the meta header. A hop field carrying a reservation is five
//! lines long instead of three, and is marked by the flyover bit in its flags byte.

pub mod layout;
pub mod types;
pub mod view;
