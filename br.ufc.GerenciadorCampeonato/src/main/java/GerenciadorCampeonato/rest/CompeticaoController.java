package GerenciadorCampeonato.rest;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import GerenciadorCampeonato.Model.Competicao;
import GerenciadorCampeonato.Model.Usuario;
import GerenciadorCampeonato.repository.CompeticaoRepository;

    @RestController
@RequestMapping("/api/competicao")
public class CompeticaoController {

    @Autowired
    CompeticaoRepository competicaoRepository;

    @GetMapping
    public List<Competicao> getAllCompeticoes() {
        return (List<Competicao>) competicaoRepository.findAll();
    }

    @GetMapping("/{id}")
    public Competicao getCompeticaoById(@PathVariable int id) {
        return competicaoRepository.findById(id).orElse(null);
    }

    @PostMapping
    public Competicao save(@RequestBody Competicao competicao) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Usuario) {
            Usuario usuario = (Usuario) authentication.getPrincipal();
            competicao.setUsuario(usuario);
            return competicaoRepository.save(competicao);
        }
        return competicao;
    }

    @GetMapping("/usuario")
    public List<Competicao> getCompeticoesDoUsuarioAutenticado() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Usuario) {
            Usuario usuario = (Usuario) authentication.getPrincipal();
            return competicaoRepository.findCompeticoesByUsuario(usuario);
        }
        return Collections.emptyList();
    }

    @PutMapping("/{id}")
    public Competicao updateCompeticao(@PathVariable int id, @RequestBody Competicao novaCompeticao) {
        Competicao competicaoExistente = competicaoRepository.findById(id).orElse(null);
        if (competicaoExistente != null) {
            competicaoExistente.setNome(novaCompeticao.getNome());
            competicaoExistente.setDescricao(novaCompeticao.getDescricao());
            competicaoExistente.setQuantTimes(novaCompeticao.getQuantTimes());
            competicaoExistente.setPremiacao(novaCompeticao.getPremiacao());
            competicaoExistente.setFormaCompeticao(novaCompeticao.getFormaCompeticao());
            return competicaoRepository.save(competicaoExistente);
        }
        return null;
    }

    @DeleteMapping("/{id}")
    public void deleteCompeticao(@PathVariable int id) {
        competicaoRepository.deleteById(id);
    }
}
