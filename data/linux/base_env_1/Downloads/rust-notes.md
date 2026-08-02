# Rust Learning Notes

## Ownership rules
1. Each value has one owner
2. Only one owner at a time
3. When owner goes out of scope, value is dropped

## Borrowing
- `&T` — immutable reference (many allowed)
- `&mut T` — mutable reference (only one at a time)
- Can't have mutable + immutable references simultaneously

## Common patterns

### Error handling
```rust
fn read_file(path: &str) -> Result<String, io::Error> {
    fs::read_to_string(path)
}

// With ? operator
fn process() -> Result<(), Box<dyn Error>> {
    let content = read_file("data.txt")?;
    println!("{}", content);
    Ok(())
}
```

### Iterators
```rust
let numbers = vec![1, 2, 3, 4, 5];
let sum: i32 = numbers.iter().filter(|&&x| x > 2).sum();
```

### Structs and impl
```rust
struct Pipeline {
    name: String,
    schedule: String,
    enabled: bool,
}

impl Pipeline {
    fn new(name: &str, schedule: &str) -> Self {
        Self {
            name: name.to_string(),
            schedule: schedule.to_string(),
            enabled: true,
        }
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}
```

## TODO
- Read chapters on traits and generics
- Try building a small CLI tool
- Look into tokio for async
