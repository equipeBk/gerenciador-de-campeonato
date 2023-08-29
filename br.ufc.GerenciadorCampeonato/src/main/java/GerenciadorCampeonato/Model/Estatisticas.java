package GerenciadorCampeonato.Model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class Estatisticas {
	@Id
	@GeneratedValue
	private int id;
	@ManyToOne
	private Partida partida;
	private String gols;
	private String cartaoAmarelo;
	private String penalts;
	private String faltas;

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public Partida getPartida() {
		return partida;
	}

	public void setPartida(Partida partida) {
		this.partida = partida;
	}

	public String getGols() {
		return gols;
	}

	public void setGols(String gols) {
		this.gols = gols;
	}

	public String getCartaoAmarelo() {
		return cartaoAmarelo;
	}

	public void setCartaoAmarelo(String cartaoAmarelo) {
		this.cartaoAmarelo = cartaoAmarelo;
	}

	public String getPenalts() {
		return penalts;
	}

	public void setPenalts(String penalts) {
		this.penalts = penalts;
	}

	public String getFaltas() {
		return faltas;
	}

	public void setFaltas(String faltas) {
		this.faltas = faltas;
	}
}
