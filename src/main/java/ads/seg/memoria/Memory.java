package ads.seg.memoria;

import ads.seg.entity.User;
import ads.seg.repository.UserRepository;

import java.util.ArrayList;

public class Memory implements UserRepository {
    private ArrayList<User> usuarios;

    @Override
    public void save(User user) {
        usuarios.add(user);
    }

    @Override
    public void update(User user) {
        for (User usuario : usuarios) {
            if (usuario.getLogin().equals(user.getLogin())) {
                usuario.setPassword(user.getPassword());
            }
        }
    }

    @Override
    public User findByLogin(String login) {
        for (User usuario : usuarios) {
            if (usuario.getLogin().equals(login)) {
                return usuario;
            }
        }

        return null;
    }
}
