package javacryption.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.text.DateFormat;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javacryption.aes.AesCtr;
import javacryption.jcryption.JCryption;

/**
 * Servlet example for jCryption
 * 
 * @author Gabriel Andery
 * @version 1.0
 */
public class CryptoServlet extends HttpServlet {

	/**
	 * serialVersionUID
	 */
	private static final long serialVersionUID = 4510110365995157499L;

	/**
	 * Handles a POST request
	 * 
	 * @see HttpServlet
	 */
	public void doPost(HttpServletRequest req, HttpServletResponse res)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		/** Generates a KeyPair for RSA **/
		if (req.getParameter("generateKeyPair") != null
				&& req.getParameter("generateKeyPair").equals("true")) {

			JCryption jc = new JCryption();
			KeyPair keys = jc.getKeyPair();
			request.getSession().getServletContext()
					.setAttribute("jCryptionKeys", keys);
			String e = jc.getPublicExponent();
			String n = jc.getKeyModulus();
			String md = String.valueOf(jc.getMaxDigits());

			/** Sends response **/
			PrintWriter out = response.getWriter();
			out.print("{\"e\":\"" + e + "\",\"n\":\"" + n
					+ "\",\"maxdigits\":\"" + md + "\"}");
			return;
		}
		/** jCryption handshake **/
		else if (req.getParameter("handshake") != null
				&& req.getParameter("handshake").equals("true")) {

			/** Decrypts password using private key **/
			JCryption jc = new JCryption((KeyPair) request.getSession()
					.getServletContext().getAttribute("jCryptionKeys"));
			String key = jc.decrypt(req.getParameter("key"));

			request.getSession().getServletContext()
					.removeAttribute("jCryptionKeys");
			request.getSession().getServletContext()
					.setAttribute("jCryptionKey", key);

			/** Encrypts password using AES **/
			String ct = AesCtr.encrypt(key, key, 256);

			/** Sends response **/
			PrintWriter out = response.getWriter();
			out.print("{\"challenge\":\"" + ct + "\"}");

			return;
		}
		/** jCryption request to decrypt a String **/
		else if (req.getParameter("decryptData") != null
				&& req.getParameter("decryptData").equals("true")
				&& req.getParameter("jCryption") != null) {

			/** Decrypts the request using password **/
			String key = (String) request.getSession().getServletContext()
					.getAttribute("jCryptionKey");

			String pt = AesCtr.decrypt(req.getParameter("jCryption"), key, 256);

			/** Sends response **/
			PrintWriter out = response.getWriter();
			out.print("{\"data\":\"" + pt + "\"}");
			return;
		}
		/** jCryption request to encrypt a String **/
		else if (req.getParameter("encryptData") != null
				&& req.getParameter("encryptData").equals("true")
				&& req.getParameter("jCryption") != null) {

			/** Encrypts the request using password **/
			String key = (String) request.getSession().getServletContext()
					.getAttribute("jCryptionKey");

			String ct = AesCtr.encrypt(req.getParameter("jCryption"), key, 256);

			/** Sends response **/
			PrintWriter out = response.getWriter();
			out.print("{\"data\":\"" + ct + "\"}");
			return;
		}
		/** A test request from jCryption **/
		else if (req.getParameter("decryptTest") != null
				&& req.getParameter("decryptTest").equals("true")) {

			/** Encrypts a timestamp **/
			String key = (String) request.getSession().getServletContext()
					.getAttribute("jCryptionKey");

			String date = DateFormat.getInstance().format(new Date());

			String ct = AesCtr.encrypt(date, key, 256);

			/** Sends response **/
			PrintWriter out = response.getWriter();
			out.print("{\"encrypted\":\"" + ct + "\", \"unencrypted\":\""
					+ date + "\"}");
			return;
		}
	}

	/**
	 * Handles a GET request
	 * 
	 * @see HttpServlet
	 */
	public void doGet(HttpServletRequest req, HttpServletResponse res)
			throws IOException, ServletException {
		doPost(req, res);
	}
}
