package ads.seg.repository;

import ads.seg.entity.User;

public interface UserRepository {
    public void save(User user);

    public void update(User user);

    public User findByLogin(String login);
}
