package ads.seg;
// Módulo que contém as classes fundamentais, como java.lang, java.util, java.io, entre outras.
import module java.base; // requer java 25
/**
 * Classe principal para testar a classe PasswordHashing com diferentes
 * algoritmos de hash.
 */
public class App {
    /**
     * Classe interna para armazenar os resultados do hash, incluindo o nome do
     * algoritmo, o tempo de execução em nanossegundos e o hash da senha em base64
     * para exibição formatada.
     */
    private record HashResult(String algorithm, String timeNanos, String base64Hash) {
    }
    private ArrayList<HashResult> results = new ArrayList<>();
    private final SecureRandom S_RANDOM = new SecureRandom();
    /**
     * Gera os hashes para cada algoritmo e mede o tempo de execução, armazenando os
     * resultados em uma lista para exibição posterior.
     *
     * @throws NoSuchAlgorithmException caso o algoritmo de hash não exista
     * @throws InvalidKeySpecException caso haja um erro na especificação da chave para PBKDF2
     */
    private void generateHashs() throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] hashedPassword = null;
        // Senha a ser testada
        // Para limpar a senha da memória, é melhor usar char[] em vez de String, pois
        // Strings são imutáveis e podem permanecer na memória por mais tempo.
        char[] password = { '1', '2', '3', '4', '5', '6' };
        // Removendo a senha da memória após o uso: Arrays.fill(password, '\0');
        // MessageDigest (MD5, SHA-1, SHA-256, SHA-512)
        String[] algorithms = { "MD5", "SHA-1", "SHA-256", "SHA-512" };
        for (String algorithm : algorithms) {
            byte[] salt = new byte[16];
            S_RANDOM.nextBytes(salt);
            long start = System.nanoTime();
            hashedPassword = PasswordHashing.hashPasswordWithMessageDigest(password, salt, algorithm);
            long end = System.nanoTime();
            String hashBase64 = encoder.encodeToString(hashedPassword != null ? hashedPassword : new byte[0]);
            results.add(new HashResult(algorithm, String.format("%,d", end - start), hashBase64));
        }
        // PBKDF2
        int iterations = 210000;
        int keyLength = 128;
        String pbkdf2Algorithm = "PBKDF2WithHmacSHA512";
        byte[] salt = new byte[16];
        S_RANDOM.nextBytes(salt);
        long start = System.nanoTime();
        hashedPassword = PasswordHashing.hashPasswordWithPBKDF2(password, salt, pbkdf2Algorithm, iterations, keyLength);
        long end = System.nanoTime();
        String hashBase64 = encoder.encodeToString(hashedPassword != null ? hashedPassword : new byte[0]);
        results.add(new HashResult(pbkdf2Algorithm, String.format("%,d", end - start), hashBase64));
        // BCrypt
        start = System.nanoTime();
        hashedPassword = PasswordHashing.hashPasswordWithBCrypt(password);
        end = System.nanoTime();
        hashBase64 = encoder.encodeToString(hashedPassword != null ? hashedPassword : new byte[0]);
        results.add(new HashResult("BCrypt", String.format("%,d", end - start), hashBase64));
    }
    /**
     * Exibe os resultados dos hashes em um formato de tabela.
     */
    private void displayResults() {
        String duracao = "Duração (ns)";
        int maxAlgorithmLength = results.stream().mapToInt(r -> r.algorithm.length()).max().orElse(0);
        int maxTimeLength = Math.max(duracao.length(),results.stream().mapToInt(r -> r.timeNanos.length()).max().orElse(0));
        int maxHashLength = results.stream().mapToInt(r -> r.base64Hash.length()).max().orElse(0);
        int totalLength = maxAlgorithmLength + maxTimeLength + maxHashLength + 9; // 7 para os espaços e bordas
        String border = String.format("+%s+", "-".repeat(totalLength));
        System.out.println(border);
        System.out.println(String.format("| %-" + (maxAlgorithmLength) + "s | ", "Algoritmo")
                + String.format("%-" + (maxTimeLength) + "s ", duracao)
                + String.format(" | %-" + (maxHashLength) + "s |", "Hash (base64)"));
        System.out.println(border);
        for (HashResult result : results) {
            String line = String.format("| %-" + (maxAlgorithmLength) + "s | ", result.algorithm)
                    + String.format("%" + (maxTimeLength) + "s | ", result.timeNanos)
                    + String.format("%-" + (maxHashLength) + "s |", result.base64Hash);
            System.out.println(line);
        }
        System.out.println(border);
    }
    public static void main(String[] args) throws IOException {
        java.util.Locale.setDefault(java.util.Locale.of("pt", "BR"));
        App app = new App();
        // Gerando os hashes e medindo o tempo de execução para cada algoritmo
        try {
            app.generateHashs();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Erro ao gerar os hashes: " + e.getMessage());
        }
        // Exibindo os resultados formatados
        app.displayResults();
        // Isso não funcionará em IDEs como IntelliJ IDEA ou se executar com o gradle
        // run,
        // pois o console não está disponível. Use o terminal ou o console do sistema
        // operacional para testar.
        // char[] s = System.console().readPassword("Entre com a senha: ");
        // System.out.println("Senha: " + new String(s));
    }
}