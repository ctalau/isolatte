```python
# Salută utilizatorul după nume
def greet(name):
    """Returnează un mesaj de bun venit prietenos."""
    # Construiește mesajul și returnează-l
    message = f"Salut, {name}! Bine ai venit la atelier."
    return message


# Punctul de intrare pentru scriptul demo
if __name__ == "__main__":
    print(greet("Alex"))
```