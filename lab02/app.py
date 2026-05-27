from flask import Flask, render_template, request
from cipher.caesar import CaesarCipher
from cipher.vigenere import VigenereCipher
from cipher.railfence import RailFenceCipher
from cipher.playfair import PlayFairCipher
from cipher.transposition import TranspositionCipher

app = Flask(__name__)

# router routes for home page
@app.route("/")
def home():
    return render_template('index.html')


# --- CAESAR CIPHER ---
@app.route("/caesar")
def caesar():
    return render_template('caesar.html')

@app.route("/caesar/encrypt", methods=['POST'])
def caesar_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    caesar = CaesarCipher()
    encrypted_text = caesar.encrypt_text(text, key)
    return render_template(
        'caesar.html',
        output=encrypted_text,
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key
    )

@app.route("/caesar/decrypt", methods=['POST'])
def caesar_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    
    hidden_plain_text = request.form.get('hiddenPlainText', '')
    hidden_key_plain = request.form.get('hiddenKeyPlain', '')
    hidden_output = request.form.get('hiddenOutput', '')
    
    caesar = CaesarCipher()
    decrypted_text = caesar.decrypt_text(text, key)
    return render_template(
        'caesar.html',
        decrypted_text=decrypted_text,
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=hidden_plain_text,
        inputKeyPlain=hidden_key_plain,
        output=hidden_output
    )


# --- VIGENERE CIPHER ---
@app.route("/vigenere")
def vigenere_route():
    return render_template('vigenere.html')

@app.route("/vigenere/encrypt", methods=['POST'])
def vigenere_encrypt():
    text = request.form['inputPlainText']
    key = request.form['inputKeyPlain']
    vigenere = VigenereCipher()
    encrypted_text = vigenere.vigenere_encrypt(text, key)
    return render_template(
        'vigenere.html',
        output=encrypted_text,
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key
    )

@app.route("/vigenere/decrypt", methods=['POST'])
def vigenere_decrypt():
    text = request.form['inputCipherText']
    key = request.form['inputKeyCipher']
    
    hidden_plain_text = request.form.get('hiddenPlainText', '')
    hidden_key_plain = request.form.get('hiddenKeyPlain', '')
    hidden_output = request.form.get('hiddenOutput', '')
    
    vigenere = VigenereCipher()
    decrypted_text = vigenere.vigenere_decrypt(text, key)
    return render_template(
        'vigenere.html',
        decrypted_text=decrypted_text,
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=hidden_plain_text,
        inputKeyPlain=hidden_key_plain,
        output=hidden_output
    )


# --- RAIL FENCE CIPHER ---
@app.route("/railfence")
def railfence_route():
    return render_template('railfence.html')

@app.route("/railfence/encrypt", methods=['POST'])
def railfence_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    railfence = RailFenceCipher()
    encrypted_text = railfence.rail_fence_encrypt(text, key)
    return render_template(
        'railfence.html',
        output=encrypted_text,
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key
    )

@app.route("/railfence/decrypt", methods=['POST'])
def railfence_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    
    hidden_plain_text = request.form.get('hiddenPlainText', '')
    hidden_key_plain = request.form.get('hiddenKeyPlain', '')
    hidden_output = request.form.get('hiddenOutput', '')
    
    railfence = RailFenceCipher()
    decrypted_text = railfence.rail_fence_decrypt(text, key)
    return render_template(
        'railfence.html',
        decrypted_text=decrypted_text,
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=hidden_plain_text,
        inputKeyPlain=hidden_key_plain,
        output=hidden_output
    )


# --- PLAYFAIR CIPHER ---
@app.route("/playfair")
def playfair_route():
    return render_template('playfair.html')

@app.route("/playfair/encrypt", methods=['POST'])
def playfair_encrypt():
    text = request.form['inputPlainText']
    key = request.form['inputKeyPlain']
    playfair = PlayFairCipher()
    matrix = playfair.create_playfair_matrix(key)
    encrypted_text = playfair.playfair_encrypt(text, matrix)
    return render_template(
        'playfair.html',
        output=encrypted_text,
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key,
        playfair_matrix=matrix
    )

@app.route("/playfair/decrypt", methods=['POST'])
def playfair_decrypt():
    text = request.form['inputCipherText']
    key = request.form['inputKeyCipher']
    
    hidden_plain_text = request.form.get('hiddenPlainText', '')
    hidden_key_plain = request.form.get('hiddenKeyPlain', '')
    hidden_output = request.form.get('hiddenOutput', '')
    
    playfair = PlayFairCipher()
    matrix = playfair.create_playfair_matrix(key)
    decrypted_text = playfair.playfair_decrypt(text, matrix)
    return render_template(
        'playfair.html',
        decrypted_text=decrypted_text,
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=hidden_plain_text,
        inputKeyPlain=hidden_key_plain,
        output=hidden_output,
        playfair_matrix=matrix
    )


# --- TRANSPOSITION CIPHER ---
@app.route("/transposition")
def transposition_route():
    return render_template('transposition.html')

@app.route("/transposition/encrypt", methods=['POST'])
def transposition_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    transposition = TranspositionCipher()
    encrypted_text = transposition.encrypt(text, key)
    return render_template(
        'transposition.html',
        output=encrypted_text,
        inputPlainText=text,
        inputKeyPlain=key,
        inputCipherText=encrypted_text,
        inputKeyCipher=key
    )

@app.route("/transposition/decrypt", methods=['POST'])
def transposition_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    
    hidden_plain_text = request.form.get('hiddenPlainText', '')
    hidden_key_plain = request.form.get('hiddenKeyPlain', '')
    hidden_output = request.form.get('hiddenOutput', '')
    
    transposition = TranspositionCipher()
    decrypted_text = transposition.decrypt(text, key)
    return render_template(
        'transposition.html',
        decrypted_text=decrypted_text,
        inputCipherText=text,
        inputKeyCipher=key,
        inputPlainText=hidden_plain_text,
        inputKeyPlain=hidden_key_plain,
        output=hidden_output
    )


# main function
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)