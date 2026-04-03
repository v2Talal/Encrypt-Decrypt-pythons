#!/usr/bin/env python3
# Sample Python file for testing encryption

def hello():
    print("Hello, World!")
    
class TestClass:
    def __init__(self):
        self.value = 42
    
    def get_value(self):
        return self.value

if __name__ == "__main__":
    hello()
    obj = TestClass()
    print(f"Value: {obj.get_value()}")
