package GerenciadorCampeonato.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import GerenciadorCampeonato.Model.Competicao;
import GerenciadorCampeonato.Model.Usuario;

@Repository
public interface CompeticaoRepository extends CrudRepository<Competicao, Integer> {

    List<Competicao> findCompeticoesByUsuario(Usuario usuario);

    }
