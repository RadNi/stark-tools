use std::ops::{Deref, DerefMut};

pub struct Parent {
    value: i32,
}

impl Parent {
    pub fn get_value(&self) -> i32 {
        self.value
    }
}

pub trait Interface {
    fn unique_behavior(&self);
}

pub struct ImplA {
    parent: Parent,
}

// "Inherit" all Parent methods
impl Deref for ImplA{
    type Target = Parent;
    fn deref(&self) -> &Self::Target {
        &self.parent
    }
}

impl DerefMut for ImplA {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.parent
    }
}

impl Interface for ImplA {
    fn unique_behavior(&self) {
        println!("ImplA's special behavior {}", self.get_value());
    }
}

pub fn main_test() {
    let mut a: Box<dyn Interface> = Box::new(ImplA { parent: Parent { value: 42 } });
    
}
