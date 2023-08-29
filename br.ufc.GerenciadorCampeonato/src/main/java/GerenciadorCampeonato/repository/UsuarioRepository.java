package GerenciadorCampeonato.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import GerenciadorCampeonato.Model.Usuario;

@Repository
public interface UsuarioRepository extends CrudRepository<Usuario, String> {

    Optional<Usuario> findById(String email);

    void deleteById(String email);

    Optional<Usuario> findUserByUsername(String username);

    Optional<Usuario> findUserByEmail(String email);

    Usuario saveAndFlush(Usuario usuario);

    }
