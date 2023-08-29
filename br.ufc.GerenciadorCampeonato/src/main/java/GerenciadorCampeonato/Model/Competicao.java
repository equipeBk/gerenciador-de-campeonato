package GerenciadorCampeonato.Model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class Competicao {
	
	@Id
	@GeneratedValue
	private int id;

	@ManyToOne
	private Usuario usuario;

	private String nome;
	private String descricao;
	private String quantTimes;
	private String premiacao;
	private String formaCompeticao;

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getDescricao() {
		return descricao;
	}

	public void setDescricao(String descricao) {
		this.descricao = descricao;
	}

	public String getQuantTimes() {
		return quantTimes;
	}

	public void setQuantTimes(String quantTimes) {
		this.quantTimes = quantTimes;
	}

	public String getPremiacao() {
		return premiacao;
	}

	public void setPremiacao(String premiacao) {
		this.premiacao = premiacao;
	}

	public String getFormaCompeticao() {
		return formaCompeticao;
	}

	public void setFormaCompeticao(String formaCompeticao) {
		this.formaCompeticao = formaCompeticao;
	}

	public void setUsuario(Usuario usuario) {
		this.usuario = usuario;
	}

}
