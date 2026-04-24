package ads.seg.service;

import ads.seg.entity.User;
import ads.seg.exception.InvalidPasswordException;
import ads.seg.exception.UserAlreadyExistsException;
import ads.seg.exception.UserNotFoundException;
import ads.seg.memoria.Memory;

import java.util.Objects;

public class UserService {

    final private Memory memory;

    public UserService(Memory memory) {
        this.memory = memory;
    }
    public void register(User usuario) throws UserAlreadyExistsException {
        if (!Objects.isNull(memory.findByLogin(usuario.getLogin()))) {
            throw new UserAlreadyExistsException("Usuário já existe");
        }

        memory.save(usuario);
    }

    public void updatePassword(User usuario, String novaSenha) throws UserNotFoundException, InvalidPasswordException {
        User usuarioExistente = memory.findByLogin(usuario.getLogin());

        if (Objects.isNull(usuarioExistente)) {
            throw new UserNotFoundException("Usuário não existe");
        }

        if (!usuario.getPassword().equals(usuarioExistente.getPassword())) {
            throw new InvalidPasswordException("Senha inválida");
        }

        usuarioExistente.setPassword(novaSenha);
        memory.update(usuarioExistente);
    }
}
