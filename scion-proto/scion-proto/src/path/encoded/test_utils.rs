//! Utilities for testing encoded views into SCION protocol structures.

#[cfg(test)]
#[macro_export]
/// Test hop field flag getters and setters
macro_rules! test_hopfield_flag {
    ($name:ident: {
        field: $field:ty,
        flag_mask: $mask:literal,
        getter: $flag_getter:tt
        $(, setter: $flag_setter:tt)?
    }) => {
        mod $name {
            use super::*;

            #[test]
            fn getter() {
                let mut backing_array = [0u8; <$field>::LENGTH];

                let field = <$field>::new(&backing_array);
                assert!(!field.$flag_getter());

                backing_array[0] = $mask;

                let field = <$field>::new(&backing_array);
                assert!(field.$flag_getter());
            }

            $(
                #[test]
                fn setter() {
                    let mut backing_array = [0u8; <$field>::LENGTH];
                    backing_array[0] = !$mask;
                    let field = <$field>::new_mut(&mut backing_array);

                    assert!(!field.$flag_getter());
                    field.$flag_setter(true);
                    assert!(field.$flag_getter());

                    let mut backing_array = [$mask; <$field>::LENGTH];
                    backing_array[0] = $mask;
                    let field = <$field>::new_mut(&mut backing_array);

                    assert!(field.$flag_getter());
                    field.$flag_setter(false);
                    assert!(!field.$flag_getter());
                }

                #[test]
                fn idempotent_set() {
                    let mut backing_array = [0u8; <$field>::LENGTH];
                    backing_array[0] = !$mask;
                    let field = <$field>::new_mut(&mut backing_array);

                    assert!(!field.$flag_getter());
                    field.$flag_setter(false);
                    assert!(!field.$flag_getter());

                    let mut backing_array = [$mask; <$field>::LENGTH];
                    backing_array[0] = $mask;
                    let field = <$field>::new_mut(&mut backing_array);

                    assert!(field.$flag_getter());
                    field.$flag_setter(true);
                    assert!(field.$flag_getter());
                }

            )?
        }
    };
}

#[cfg(test)]
#[macro_export]
/// Test a function with the given arguments
/// Example usage:
/// ```
/// fn check_sum(a: i32, b: i32) {
///    assert_eq!(a + b, add(2, 3));
/// }
///
/// test_case!(test_add: check_sum(2, 3));
/// ```
/// This will create a test function named `test_add` that calls `check_sum(2, 3)`. 
macro_rules! test_case {
    ($name:ident: $func:ident($arg1:expr$(, $arg:expr)*)) => {
        #[test]
        fn $name() {
            $func($arg1 $(, $arg)*)
        }
    };
}
