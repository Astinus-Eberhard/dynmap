package org.dynmap.servlet;

import static org.dynmap.JSONUtils.s;

import org.dynmap.DynmapCore;
import org.dynmap.Log;
import org.json.simple.JSONObject;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.dynmap.utils.IpAddressMatcher;

public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private DynmapCore core;
    public static final String USERID_GUEST = "_guest_";
    public static final String USERID_ATTRIB = "userid";
    public static final String LOGIN_PAGE = "../login.html";
    public static final String LOGIN_POST = "/up/login";
    private Charset cs_utf8 = Charset.forName("UTF-8");
    public ArrayList<IpAddressMatcher> proxyaddress = new ArrayList<IpAddressMatcher>();

    public LoginServlet(DynmapCore core) {
        this.core = core;
        final List<String> trustedproxy = core.configuration.getStrings("trusted-proxies", null);
        if(trustedproxy != null) {
            for(String s : trustedproxy) {
                this.proxyaddress.add(new IpAddressMatcher(s.trim()));
            }
        }
        else {
            this.proxyaddress.add(new IpAddressMatcher("127.0.0.1"));
            this.proxyaddress.add(new IpAddressMatcher("0:0:0:0:0:0:0:1"));
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doPost(req, resp);
    }
    
    private void sendResponse(HttpServletResponse resp, String rslt) throws ServletException, IOException {
        JSONObject json = new JSONObject();
        s(json, "result", rslt);
        byte[] b = json.toJSONString().getBytes(cs_utf8);
        String dateStr = new Date().toString();
        resp.addHeader("Date", dateStr);
        resp.setContentType("text/plain; charset=utf-8");
        resp.addHeader("Expires", "Thu, 01 Dec 1994 16:00:00 GMT");
        resp.addHeader("Last-modified", dateStr);
        resp.setContentLength(b.length);
        resp.getOutputStream().write(b);
    }

    private boolean trustedProxy(String ip) {
    	for (IpAddressMatcher m : proxyaddress) {
    		if (m.matches(ip)) {
    			return true;
    		}
    	}
    	return false;
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        /* Get session - initialize if needed */
        HttpSession sess = req.getSession(true);
        String uid = (String)sess.getAttribute(USERID_ATTRIB);
        if(uid == null) {
            uid = USERID_GUEST;
            sess.setAttribute(USERID_ATTRIB, uid);   /* Set to guest access */
        }
        if(sess.isNew()) {
            sess.setMaxInactiveInterval(60);    /* Intialize to 60 seconds */
        }
        
        /* If from trusted proxy, check for client */
        String rmtaddr = req.getRemoteAddr();
        if (this.trustedProxy(rmtaddr)) {	// If remote address is valid trusted proxy
            /* If proxied client address, get original IP */
            if (req.getHeader("X-Forwarded-For") != null) {
                // Split list, since addresses after first are proxy chain
                String[] proxyAddrs = req.getHeader("X-Forwarded-For").split(",");
                // We only want first - any others are proxies that our local proxy was willing to pass to us
                rmtaddr = proxyAddrs[0].trim();
            }
        }

        String uri = req.getRequestURI();
        if(uri.equals("/up/login")) {  /* Process login form */
            uid = req.getParameter("j_username");
            String pwd = req.getParameter("j_password");
            if((uid == null) || (uid.equals("")))
                uid = USERID_GUEST;
            if(core.checkLogin(uid, pwd)) {
                Log.info("User " + uid + " logged in from " + rmtaddr);
                sess.setAttribute(USERID_ATTRIB, uid);
                sendResponse(resp, "success");
            }
            else {
                Log.warning("User " + uid + " failed to log in from " + rmtaddr);
                sendResponse(resp, "loginfailed");
            }
        }
        else if(uri.equals("/up/register")) {  /* Process register form */
            uid = req.getParameter("j_username");
            String pwd = req.getParameter("j_password");
            String vpwd = req.getParameter("j_verify_password");
            String passcode = req.getParameter("j_passcode");
            if((pwd == null) || (vpwd == null) || (pwd.equals(vpwd) == false)) {
                resp.sendRedirect(LOGIN_PAGE + "?error=verifyfailed");
                sendResponse(resp, "verifyfailed");
            }
            else if(core.registerLogin(uid, pwd, passcode)) {    /* Good registration? */
                Log.info("User " + uid + " registered successfully from " + rmtaddr);
                sess.setAttribute(USERID_ATTRIB, uid);
                sendResponse(resp, "success");
            }
            else {
                Log.warning("User " + uid + " failed to registered from " + rmtaddr);
                sendResponse(resp, "registerfailed");
            }
        }
        else {
            Log.severe("User failed to log in from " + rmtaddr);
            sendResponse(resp, "loginfailed");
        }
    }

    @Override
    public void destroy() { }
}
