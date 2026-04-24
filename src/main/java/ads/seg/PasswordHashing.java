package ads.seg;
// Módulo que contém as classes fundamentais, como java.lang, java.util, java.io, entre outras.
import module java.base; // requer java 25
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
/**
 * Classe utilitária para realizar o hash de senhas com diferentes algoritmos.
 *
 * Algoritmos de hash com message digest: MD5, SHA-1, SHA-256, SHA-512
 * Algoritmos de hash com PBKDF2: PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA512
 * BCrypt é um algoritmo de hash de senhas
 *
 */
public abstract class PasswordHashing {
    // Charset padrão para codificação de strings
    private static final Charset charset = StandardCharsets.UTF_8;
    /**
     * Método que recebe uma senha e a converte para um array de bytes
     * @param password senha do usuário em formato char[]
     * @return array de bytes da senha
     * @throws CharacterCodingException caso ocorra um erro de codificação
     */
    private static byte[] convertCharToByte(char[] password) {
        byte[] bytePassword = new byte[0];
        try {
            CharsetEncoder encoder = PasswordHashing.charset.newEncoder();
            CharBuffer charBuffer = CharBuffer.wrap(password);
            ByteBuffer byteBuffer = encoder.encode(charBuffer);
            bytePassword = new byte[byteBuffer.remaining()];
            byteBuffer.get(bytePassword);
        } catch (CharacterCodingException e) {
            throw new RuntimeException("Erro ao codificar", e);
        }
        return bytePassword;
    }
/**
 * Método que recebe uma senha, um salt e um algoritmo de hash e retorna o hash da senha
 * @param password senha do usuário
 * @param salt salt aleatório
 * @param algorithm algoritmo de hash
 * @return hash da senha
 * @throws NoSuchAlgorithmException caso o algoritmo de hash não exista
 */
public static byte[] hashPasswordWithMessageDigest(char[] password, byte[] salt, String algorithm) throws
        NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(salt);
    return md.digest(convertCharToByte(password));
}
    /**
     * Método que verifica se a senha fornecida é igual ao hash da senha armazenado
     * @param password senha do usuário
     * @param salt salt aleatório
     * @param algorithm algoritmo de hash
     * @param hashedPassword hash da senha armazenado
     * @return true se a senha fornecida é igual ao hash da senha armazenado, false caso contrário
     * @throws NoSuchAlgorithmException caso o algoritmo de hash não exista
     */
    public static boolean verifyPasswordWithMessageDigest(char[] password, byte[] salt, String algorithm, byte[]
            hashedPassword) throws NoSuchAlgorithmException {
        return MessageDigest.isEqual(hashPasswordWithMessageDigest(password, salt, algorithm),hashedPassword);
    }
    /**
     * Método que recebe uma senha, um salt, um algoritmo de hash, número de iterações e tamanho da chave e retorna o hash da
     senha
     * @param password senha do usuário
     * @param salt salt aleatório
     * @param algorithm algoritmo de hash
     * @param iterations número de iterações
     * @param keyLength tamanho da chave
     * @return hash da senha
     * @throws NoSuchAlgorithmException caso o algoritmo de hash não exista
     * @throws InvalidKeySpecException caso a chave seja inválida
     */
    public static byte[] hashPasswordWithPBKDF2(char[] password, byte[] salt, String algorithm, int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        return SecretKeyFactory.getInstance(algorithm).generateSecret(spec).getEncoded();
    }
    /**
     * Método que verifica se a senha fornecida é igual ao hash da senha armazenado
     * @param password senha do usuário
     * @param salt salt aleatório
     * @param algorithm algoritmo de hash
     * @param iterations número de iterações
     * @param keyLength tamanho da chave
     * @param hashedPassword hash da senha armazenado
     * @return true se a senha fornecida é igual ao hash da senha armazenado, false caso contrário
     * @throws NoSuchAlgorithmException caso o algoritmo de hash não exista
     * @throws InvalidKeySpecException caso a chave seja inválida
     */
    public static boolean verifyPasswordWithPBKDF2(char[] password, byte[] salt, String algorithm, int iterations, int
            keyLength, byte[] hashedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(hashPasswordWithPBKDF2(password, salt, algorithm, iterations, keyLength)).equals(encoder
                .encodeToString(hashedPassword));
    }
/**
 * Método que recebe uma senha e retorna o hash da senha com BCrypt
 *
 * Não é necessário fornecer um salt, pois o BCrypt já gera um salt aleatório internamente
 * @param password senha do usuário
 * @return hash da senha
 */
public static byte[] hashPasswordWithBCrypt(char[] password) {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    return encoder.encode(CharBuffer.wrap(password)).getBytes(PasswordHashing.charset);
}
    /**
     * Método que verifica se a senha fornecida é igual ao hash da senha armazenado com BCrypt
     *
     * Não é necessário fornecer um salt, pois o BCrypt já gera um salt aleatório internamente
     * @param password senha do usuário
     * @param hashedPassword hash da senha armazenado
     * @return true se a senha fornecida é igual ao hash da senha armazenado, false caso contrário
     */
    public static boolean verifyPasswordWithBCrypt(char[] password, byte[] hashedPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(CharBuffer.wrap(password), new String(hashedPassword, PasswordHashing.charset));
    }
}