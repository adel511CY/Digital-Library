const bcrypt = require("bcrypt")
const db = require("better-sqlite3")("web.db")

// ---------- admin ----------
const adminPassword = "admin"
const adminHash = bcrypt.hashSync(adminPassword, bcrypt.genSaltSync(10))

const existing = db.prepare("SELECT id FROM users WHERE username = ?").get("admin")

if (existing) {
    db.prepare("UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?")
      .run(adminHash, existing.id)
    console.log("Admin already existed, password reset and is_admin = 1")
} else {
    db.prepare(`
        INSERT INTO users (username, email, password_hash, full_name, is_admin)
        VALUES (?, ?, ?, ?, 1)
    `).run("admin", "admin@library.com", adminHash, "System Administrator")
    console.log("Admin created")
}

// ---------- books ----------
const cover = (isbn) => `https://covers.openlibrary.org/b/isbn/${isbn}-L.jpg`

const books = [
    // Programming & CS
    ["Clean Code", "Robert C. Martin", "A handbook of agile software craftsmanship and writing readable code.", "9780132350884", 8],
    ["The Pragmatic Programmer", "Andrew Hunt, David Thomas", "Practical advice for becoming a better, more effective developer.", "9780135957059", 6],
    ["Introduction to Algorithms", "Thomas H. Cormen et al.", "The standard reference on algorithms and data structures.", "9780262046305", 5],
    ["Design Patterns", "Erich Gamma et al.", "Reusable object-oriented software design patterns.", "9780201633610", 4],
    ["The Rust Programming Language", "Steve Klabnik, Carol Nichols", "The official book on Rust, from ownership to concurrency.", "9781718503106", 7],
    ["Operating System Concepts", "Abraham Silberschatz et al.", "Core concepts of modern operating systems.", "9781118063330", 5],

    // Security
    ["Applied Cryptography", "Bruce Schneier", "Protocols, algorithms, and source code in C.", "9781119096726", 4],
    ["Cryptography Engineering", "Niels Ferguson, Bruce Schneier, Tadayoshi Kohno", "Design principles and practical applications of cryptography.", "9780470474242", 4],
    ["The Web Application Hacker's Handbook", "Dafydd Stuttard, Marcus Pinto", "Finding and exploiting security flaws in web applications.", "9781118026472", 5],

    // Science
    ["A Brief History of Time", "Stephen Hawking", "From the Big Bang to black holes, explained for general readers.", "9780553380163", 6],
    ["Cosmos", "Carl Sagan", "A journey through the universe and the history of science.", "9780345539434", 5],
    ["The Selfish Gene", "Richard Dawkins", "A gene-centered view of evolution.", "9780198788607", 4],
    ["Gödel, Escher, Bach", "Douglas Hofstadter", "An exploration of minds, machines, and mathematical patterns.", "9780465026562", 3],

    // Classic & modern fiction
    ["1984", "George Orwell", "A dystopian novel about totalitarianism and surveillance.", "9780451524935", 10],
    ["Brave New World", "Aldous Huxley", "A future society engineered for stability and conformity.", "9780060850524", 6],
    ["Fahrenheit 451", "Ray Bradbury", "A world where books are banned and burned.", "9781451673319", 6],
    ["To Kill a Mockingbird", "Harper Lee", "Justice and racism in the American South seen through a child's eyes.", "9780061120084", 7],
    ["The Great Gatsby", "F. Scott Fitzgerald", "Wealth, love, and the American dream in the Jazz Age.", "9780743273565", 7],
    ["Pride and Prejudice", "Jane Austen", "A witty story of manners, marriage, and misunderstandings.", "9780141439518", 5],
    ["The Catcher in the Rye", "J. D. Salinger", "A teenager's restless wandering through New York City.", "9780316769488", 4],
    ["One Hundred Years of Solitude", "Gabriel García Márquez", "The multi-generational story of the Buendía family.", "9780060883287", 4],
    ["The Kite Runner", "Khaled Hosseini", "Friendship, guilt, and redemption in Afghanistan.", "9781594631931", 6],
    ["The Little Prince", "Antoine de Saint-Exupéry", "A poetic tale about love, loss, and what really matters.", "9780156012195", 8],

    // Fantasy & sci-fi
    ["The Hobbit", "J. R. R. Tolkien", "Bilbo Baggins' unexpected adventure with dwarves and a dragon.", "9780547928227", 8],
    ["The Lord of the Rings", "J. R. R. Tolkien", "The epic quest to destroy the One Ring.", "9780544003415", 6],
    ["Dune", "Frank Herbert", "Politics, religion, and ecology on the desert planet Arrakis.", "9780441172719", 6],
    ["Harry Potter and the Sorcerer's Stone", "J. K. Rowling", "A boy discovers he is a wizard and enters Hogwarts.", "9780590353427", 9],

    // Self-development, business & history
    ["Atomic Habits", "James Clear", "A practical system for building good habits and breaking bad ones.", "9780735211292", 10],
    ["Thinking, Fast and Slow", "Daniel Kahneman", "How two systems of thought shape our decisions.", "9780374533557", 5],
    ["Sapiens", "Yuval Noah Harari", "A brief history of humankind.", "9780062316097", 7],
    ["Man's Search for Meaning", "Viktor E. Frankl", "Lessons on purpose drawn from the Holocaust.", "9780807014295", 5],
    ["Zero to One", "Peter Thiel", "Notes on startups and building the future.", "9780804139298", 4],
    ["The Muqaddimah", "Ibn Khaldun", "An introduction to history and a pioneering work of sociology.", "9780691166285", 4],
]

const insertBook = db.prepare(`
    INSERT OR IGNORE INTO books
    (title, author, description, isbn, quantity, available_quantity, image_url)
    VALUES (?, ?, ?, ?, ?, ?, ?)
`)

const seedBooks = db.transaction(() => {
    let added = 0
    for (const [title, author, description, isbn, qty] of books) {
        const r = insertBook.run(title, author, description, isbn, qty, qty, cover(isbn))
        added += r.changes
    }
    return added
})

console.log(`Books added: ${seedBooks()} / ${books.length}`)