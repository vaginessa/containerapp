/*
 * Copyright (c) 2014, North Carolina State University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of North Carolina State University nor the names of
 * its contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */

package com.example.containerapp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.BrowserCompatHostnameVerifier;

import android.net.Uri;
import android.os.Bundle;
import android.os.StrictMode;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.GeolocationPermissions;
import android.webkit.ValueCallback;
import android.webkit.WebSettings;
import android.webkit.WebSettings.PluginState;
import android.webkit.WebStorage;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebChromeClient;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import android.widget.Toast;

public class ContainerMain extends Activity {
	private View mCustomView;
	private RelativeLayout mContentView;
	private FrameLayout mCustomViewContainer;
	private WebChromeClient.CustomViewCallback mCustomViewCallback;
	
	MyWebChromeClient mWebChromeClient = new MyWebChromeClient();
	static String fixedURL;
	WebView mywebview;
	X509Certificate maincert=null;
	Context context=null;
	File rootcertfile = null;
	KeyStore mykey = null;
	boolean matchOrigin=true;
	boolean rulePresent=false;
	static String fromRule=null;
	static String toRule=null;
	static String TAG=""; 
	ArrayList<String> whiteList = new ArrayList<String>();

	private final static int FILECHOOSER_RESULTCODE=1;
	private ValueCallback<Uri> mUploadMessage;  

	@Override  
	protected void onActivityResult(int requestCode, int resultCode,  
	                                    Intent intent) {
		if(requestCode==FILECHOOSER_RESULTCODE)  
		{  
			if (null == mUploadMessage) return;  
	        Uri result = intent == null || resultCode != RESULT_OK ? null : intent.getData();  
	        mUploadMessage.onReceiveValue(result);  
	        mUploadMessage = null;  
		}
	}
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		context=getApplicationContext();
		setContentView(R.layout.activity_container_main);
		StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        TAG+=this.getApplicationInfo().name;
		
		//Initialize the whitelist
		whiteList.add("facebook.com");
		whiteList.add("accounts.google.com");
		
		//The rootcertfile will store the Root CA's certificate, initialized on first use.
		rootcertfile= new File(context.getFilesDir()+"/rootcertfile");
		
		//Get the url from assets
		AssetManager assetManager = getAssets();
		try {
			InputStream fis = assetManager.open("default_url.xml");
			String stringValue=convertStreamToString(fis);
			String stringArray[]=stringValue.split("\n");
			fixedURL = stringArray[0];
			if(stringArray.length>1 && stringArray[1].equalsIgnoreCase("false"))
				matchOrigin=false;
			else
				matchOrigin=true;
			//For ForceHTTPS, check if fromRule and toRule were packaged with this app
			if(stringArray.length>2){
				fromRule = stringArray[2];
				toRule = stringArray[3];
				if(fromRule!=null && toRule!=null && !fromRule.equals("") && !toRule.equals(""))
					rulePresent=true;
			}
			if(fixedURL == null || fixedURL.equals(""))
			{
				//Just in case, should never happen
				Log.d(TAG,"ERROR!Could not get URL from assets! Defaulting to https://www.google.com.");
				fixedURL="https://www.google.com";
			}
			else 
			{
				Log.d(TAG,"Pinning to URL "+fixedURL+ " from assets!");
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			Log.d(TAG,"Exception while recovering url from xml asset");
			e.printStackTrace();
		}
		
		
		/* Root CA Certificate Pinning:
		 * Get the initial Root CA Cert and pin to it.
		 * If https, then first get the server's certificate
		 * Then, climb up the certificate chain and get the Root CA's certificate
		 * Override the webview's TrustManager with a new TrustManager that uses only this root CA.
		 * */
		final URL urlfromfile;
		try {
			urlfromfile=new URL(fixedURL);
			String protocol=urlfromfile.getProtocol();
			if(protocol.equalsIgnoreCase("https"))
			{
				if(!rootcertfile.exists())
				{
					Log.d(TAG,"Acquiring Root CA Cert for the first time for "+urlfromfile.toString());	
					HttpsURLConnection con=null;
					try {
						InitialX509TrustManager tm = new InitialX509TrustManager();
						TrustManager[] tmarray = new TrustManager[1];
						tmarray[0]=tm;
						SSLContext sslcontext = SSLContext.getInstance("TLS");
						sslcontext.init(null, tmarray, null);	
						con = (HttpsURLConnection)urlfromfile.openConnection();
						con.setSSLSocketFactory(sslcontext.getSocketFactory());
						InputStream in = con.getInputStream();
						if(in!=null) in.close();
						if(con!=null) con.disconnect();
					}
					catch (Exception e) {
						// TODO Auto-generated catch block
						Log.d(TAG,"Exception while initializing root Cert"+e);
					}
				}
				else
				{	//Retrieve the Root CA Certificate that previously saved in the rootcertfile.
					try{
				      InputStream file = new FileInputStream(rootcertfile);
				      InputStream buffer = new BufferedInputStream( file );
				      ObjectInput input = new ObjectInputStream ( buffer );
				      try{
				        //deserialize the certificate
				        maincert = (X509Certificate)input.readObject();
				        //Print Cert for debug.
				        //System.out.println(maincert.toString());
				      }
				      finally{
				        if(input!=null) input.close();
				        if(buffer!=null) buffer.close();
				        if(file!=null) file.close();
				      }
				    }
				    catch(ClassNotFoundException e){
				        e.printStackTrace();
				    }
				    catch(IOException e){
				    	e.printStackTrace();
				    }
					//Creating a keystore with a certificate
					if(maincert!=null) {	
						mykey = KeyStore.getInstance("BKS");
						mykey.load(null, null);
						mykey.setCertificateEntry("MainCert", maincert);
					}
					else {
						Log.d(TAG,"Maincert is null while creating Keystore!!");
					}
				}
			}
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		//Load url into webview
		//mywebview = new android.webkit.WebView(this);
		mywebview = (WebView) findViewById(R.id.webview);
		mywebview.loadUrl(fixedURL);
		mywebview.setEnabled(true);
		mywebview.setFocusable(true);
		
		mywebview.requestFocus();
		
		//Now Configure the WebView.
		//Enable javascript.
		WebSettings webSettings = mywebview.getSettings();
		webSettings.setJavaScriptEnabled(true);
		
		//Other settings to make pages sizing better, html5 compatibility, etc.
		webSettings.setDomStorageEnabled(true);
		webSettings.setBuiltInZoomControls(true);
		webSettings.setLayoutAlgorithm(WebSettings.LayoutAlgorithm.NARROW_COLUMNS);
		webSettings.setUseWideViewPort(true);
		webSettings.setLoadWithOverviewMode(true);
		webSettings.setPluginState(PluginState.ON_DEMAND);
		webSettings.setSaveFormData(true);
		webSettings.setGeolocationEnabled(true);
		//Database Support
		webSettings.setDatabaseEnabled(true);
		String databasePath = this.getApplicationContext().getDir("wrapdatabase",
			    Context.MODE_PRIVATE).getPath();
		webSettings.setDatabasePath(databasePath);
		webSettings.setAllowFileAccess(true);

		//Configuring App cache
		webSettings.setAppCacheEnabled(true);
		webSettings.setAppCachePath("/data/data/" + getPackageName() + "/cache/");
		webSettings.setAppCacheMaxSize(1024*1024*8);
	
		//Enabling light touch and mouse-overs
		webSettings.setLightTouchEnabled(true);
		
		//Adding zoom controls
		webSettings.setBuiltInZoomControls(true);
		
		//Handling page navigation
		mywebview.setWebViewClient(new MyWebViewClient());
		
		//Setting the Chrome Client
		//MyWebChromeClient mWebChromeClient = new MyWebChromeClient();
	    mywebview.setWebChromeClient(mWebChromeClient);
	    
		//Enabling Cookies
		 CookieManager cookieManager = CookieManager.getInstance(); 
	     cookieManager.setAcceptCookie(true); 	
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.activity_container_main, menu);
		return true;
	}
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
	    // Handle item selection
	    switch (item.getItemId()) {
	        case R.id.refresh:
	            mywebview.reload();
	            return true;
	        default:
	            return super.onOptionsItemSelected(item);
	    }
	}
	
	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
	    if ((keyCode == KeyEvent.KEYCODE_BACK) && mywebview.canGoBack()) {
	        mywebview.goBack();
	        return true;
	    }
	    return super.onKeyDown(keyCode, event);
	}
	
	@Override
	public void onBackPressed() {
	    if (mCustomViewContainer != null)
	        mWebChromeClient.onHideCustomView();
	    else if (mywebview.canGoBack())
	        mywebview.goBack();
	    else
	        super.onBackPressed();
	}
	
	public static String convertStreamToString(java.io.InputStream is) {
	    java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
	    return s.hasNext() ? s.next() : "";
	}
	

	//MyWebViewClient: Controls navigation. 
	private class MyWebViewClient extends WebViewClient {
	    @Override
	    public boolean shouldOverrideUrlLoading(WebView view, String url) {	
	    	//Compare the hostnames of the origURL and the currentURL, to decide whether to 
	    	//continue in the webview or not	
	    	//return false to load in WebView; if true, send an intent to the Web browser
	    
	    	URL origURL=null;
	    	URL currentURL= null;
	    	try {
			    origURL = new URL(fixedURL);
				currentURL = new URL(url);
		
			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
	    	
	    	if(origURL==null || currentURL==null)
	    		return false;
	    	
	    	//HTTPS -> HTTP, check if rule exists, if it does then replace with https  
	    	if(origURL.getProtocol().equals("https")&&(currentURL.getProtocol().equals("http"))&&rulePresent){
	    		try {
					currentURL=new URL(currentURL.toString().replaceAll(fromRule,toRule));
				} catch (MalformedURLException e) {
					// TODO Auto-generated catch block
					Log.d(TAG,"While matching HTTPSEverywhere rule.");
					e.printStackTrace();
				}
	    	}
	    	
	    	//Comparing Current URL with WhiteList
	    	//If it exists in the white list, let it load
	    	ListIterator<String> whiteListIterator = whiteList.listIterator();
	    	if(whiteList.isEmpty())
	    		Log.d(TAG,"Empty Whitelist!");
	    	while(whiteListIterator.hasNext()){
	    		String temp=whiteListIterator.next();
	    		if(temp.equals(currentURL.getHost()))
	    		{	
	    			showToast("WhiteList: "+url);
	    			return false;
	    		}
	    	}

    		//Check entire host first; to prevent additional overhead of obtaining the origin domain and matching it.	
    		if (origURL.getHost().equals(currentURL.getHost())) {
    			if(!checkHTTPSConnection(currentURL, view))
    				return false;
    		}
    		try{
		    	//If pinned to the second level domain, i.e. the origin.
		    	if(matchOrigin)
		    	{ 
			    	//Compare the second level domain ("bestbuy.com" from www-ssl.bestbuy.com)
			    	String arrayOrig[] = (origURL.getHost()+"").split("\\.");
			    	String arrayCurrent[] = (currentURL.getHost()+"").split("\\.");
			    	Log.d(TAG,arrayOrig+ " | "+arrayCurrent);
			    	int lenOrig = arrayOrig.length, lenCurr = arrayCurrent.length;
			    	int origIndex=0, currIndex=0;
			    	if(arrayOrig[lenOrig-1].length()<=2 && arrayOrig[lenOrig-2].length()<=2)
			    		origIndex=3;//i.e. third from the end
			    	else origIndex=2;//i.e. 2nd from the end
			    	if(arrayCurrent[lenCurr-1].length()<=2 && arrayCurrent[lenCurr-2].length()<=2)
			    		currIndex=3;
			    	else currIndex=2;
		 
			    	String origDomainToMatch="", currDomainToMatch="";
			    	while(origIndex>0){
			    		//System.out.println("Matching:"+origIndex+": "+origDomainToMatch);
			    		origDomainToMatch+=arrayOrig[lenOrig-origIndex];
			    		origIndex--;
			    	}
			    	while(currIndex>0){
			    		//System.out.println("Matching:"+currIndex+":"+currDomainToMatch);
			    		currDomainToMatch+=arrayCurrent[lenCurr-currIndex];
			    		currIndex--;
			    	}
		    		if(origDomainToMatch.equals(currDomainToMatch)){
		    			Log.d(TAG,"Matched "+origDomainToMatch);
		    			//checkHTTPSConnection returns true when certificate DOES NOT match, 
		    			//we return false to indicate loading in the webview app.
		    			if(!checkHTTPSConnection(currentURL, view))
		    				return false;
		    		}
		    	}
    		}
	    	catch(Exception e){
	    		Log.d(TAG, "Origin check exception:", e);
	    		e.printStackTrace();
	    	}
	        // Otherwise, the link is not for a page on my site, so launch another Activity that handles URLs
	    	showToast("Mismatched URL:"+url);
	        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
	        Log.d(TAG,"URL Domain: "+fixedURL);
	        Log.d(TAG,"URL Accessed: "+url);
	        startActivity(intent);	        
	        return true;
	    }
	    public void openFileChooser( ValueCallback<Uri> uploadMsg, String acceptType ) 
	    {  
	        this.openFileChooser(uploadMsg, acceptType);
	    }
	    
	}
	//Display a Toast
	private void showToast(String toastText){
		Context context = getApplicationContext();
		int duration = Toast.LENGTH_SHORT;
		Toast toast = Toast.makeText(context, toastText, duration);
		toast.show();
	}
	
	//Check if a valid HTTPS connection can be formed
	boolean checkHTTPSConnection(URL currentURL, WebView view)
	{//returns false on valid certificate verification.
		boolean retFlag=false;
		if(currentURL.getProtocol().equals("https"))
		{
			try {
				TrustManager trustman = new MyX509TrustManager();
				/******/
				TrustManager[] tms = new TrustManager[] {trustman};
				SSLContext sslctx = SSLContext.getInstance("SSL");
                sslctx.init(null,  tms, null);                 
                HttpsURLConnection uc = (HttpsURLConnection)currentURL.openConnection();
    			Log.d(TAG,"Loaded the https  url");
    			uc.setSSLSocketFactory(sslctx.getSocketFactory());
    			//Log.i(TAG,uc.getHostnameVerifier().toString());
    			InputStream inp = uc.getInputStream();
    			Log.d(TAG,"Connection succeeded:"+currentURL.toString());
    			//op=readStream(inp);
    			//view.loadData(op, "text/HTML", "UTF-8");
    			if(inp!=null)
    				inp.close();
    			uc.disconnect();
				
			} catch (Exception e) {
				// TODO Auto-generated catch block
				retFlag=true;//If SSL check failsm return true. 
				Log.d(TAG,"Could Not make an SSL Connection"+e);
			}
		}
		
		return retFlag;
	}
	
	//The Chrome Client for uploading files.
	private class MyWebChromeClient extends WebChromeClient {

		FrameLayout.LayoutParams LayoutParameters = new FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT,
	            FrameLayout.LayoutParams.MATCH_PARENT);
		
		public void openFileChooser(ValueCallback<Uri> uploadMsg) {  

            mUploadMessage = uploadMsg;  
            Intent i = new Intent(Intent.ACTION_GET_CONTENT);  
            i.addCategory(Intent.CATEGORY_OPENABLE);  
            i.setType("image/*");  
            ContainerMain.this.startActivityForResult(Intent.createChooser(i,"File Chooser"), FILECHOOSER_RESULTCODE);  

           }

           public void openFileChooser( ValueCallback uploadMsg, String acceptType ) {
           mUploadMessage = uploadMsg;
           Intent i = new Intent(Intent.ACTION_GET_CONTENT);
           i.addCategory(Intent.CATEGORY_OPENABLE);
           i.setType("*/*");
           ContainerMain.this.startActivityForResult(
           Intent.createChooser(i, "File Browser"),
           FILECHOOSER_RESULTCODE);
           }

           public void openFileChooser(ValueCallback<Uri> uploadMsg, String acceptType, String capture){
               mUploadMessage = uploadMsg;  
               Intent i = new Intent(Intent.ACTION_GET_CONTENT);  
               i.addCategory(Intent.CATEGORY_OPENABLE);  
               i.setType("image/*");  
               ContainerMain.this.startActivityForResult( Intent.createChooser( i, "File Chooser" ), ContainerMain.FILECHOOSER_RESULTCODE );

           }
         @Override
         public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
             callback.invoke(origin, true, false);
         }
         
         @Override
         public void onExceededDatabaseQuota(String url, String databaseIdentifier, long currentQuota, long estimatedSize,
             long totalUsedQuota, WebStorage.QuotaUpdater quotaUpdater) {
             quotaUpdater.updateQuota(estimatedSize * 2);
         }  
         
         //Handling HTML5 Video
         @Override
         public void onShowCustomView(View view, CustomViewCallback callback) {
             // if a view already exists then immediately terminate the new one
             if (mCustomView != null) {
                 callback.onCustomViewHidden();
                 return;
             }
             mContentView = (RelativeLayout) findViewById(R.id.relativelayout);
             mContentView.setVisibility(View.GONE);
             mCustomViewContainer = new FrameLayout(ContainerMain.this);
             mCustomViewContainer.setLayoutParams(LayoutParameters);
             mCustomViewContainer.setBackgroundResource(android.R.color.black);
             view.setLayoutParams(LayoutParameters);
             mCustomViewContainer.addView(view);
             mCustomView = view;
             mCustomViewCallback = callback;
             mCustomViewContainer.setVisibility(View.VISIBLE);
             setContentView(mCustomViewContainer);
         }

         @Override
         public void onHideCustomView() {
             if (mCustomView == null) {
            	 mCustomViewContainer=null;
                 return;
             } else {
                 // Hide the custom view.  
                 mCustomView.setVisibility(View.GONE);
                 // Remove the custom view from its container.  
                 mCustomViewContainer.removeView(mCustomView);
                 mCustomView = null;
                 mCustomViewContainer.setVisibility(View.GONE);
                 mCustomViewCallback.onCustomViewHidden();
                 // Show the content view.  
                 mContentView.setVisibility(View.VISIBLE);
                 setContentView(mContentView);
                 mCustomViewContainer=null;
             }
         }
    }

	/*****************
	 * TrustManager implementation for 
	 * SSL Pinning with maincert as the root CA cert and 
	 * mykey as the keystore.
	 * Not used for initializing the root CA cert.
	 */
	public class MyX509TrustManager
    implements X509TrustManager
    {

		private X509TrustManager selfTrustManager = null;
		List<X509Certificate> allIssuers = new ArrayList<X509Certificate>();
		/**
		 * Constructor for MyX509TrustManager. 
		 * 
		 */
	    public MyX509TrustManager() throws NoSuchAlgorithmException, KeyStoreException {
	        super();
	        TrustManagerFactory selffactory = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
	        if(mykey==null)
	        {	//System.out.println("MYKEY NULL");
	        	selffactory.init((KeyStore)mykey); // Initialize TMF with self signed cert keystore
	        }
	        else
	        	selffactory.init(mykey); 
	        TrustManager[] selftm = selffactory.getTrustManagers();
	       
	        if ( selftm.length == 0 )
	        {
	            throw new NoSuchAlgorithmException( "no trust manager found" );
	        }
	        this.selfTrustManager = (X509TrustManager) selftm[0];
	
	    }

	    /**
	     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(X509Certificate[],String authType)
	     */
	    public void checkClientTrusted( X509Certificate[] certificates, String authType )
	        throws CertificateException {
	    	try{
	    		selfTrustManager.checkClientTrusted( certificates, authType );	
	    	}
	    	catch(CertificateException e)
	    	{
	    		Log.d(TAG,"Exception while initializing TrustManager: checkClientTrusted:"+e);
	    	}
	        
	    }	

	    /**
	     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(X509Certificate[],String authType)
	     */
	    public void checkServerTrusted( X509Certificate[] certificates, String authType )
	        throws CertificateException {
	    		Log.d(TAG,"Inside My Trust Manager.");
	    		selfTrustManager.checkServerTrusted( certificates, authType );
	    }

	    /**
	     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
	     */
	    public X509Certificate[] getAcceptedIssuers() {
	    	return null;
	    }

    }
	
	/*****************
	 * TrustManager implementation 
	 * For Acquiring and Initializing the root CA cert for pinning.
	 */
	public class InitialX509TrustManager
    implements X509TrustManager
    {
		private X509TrustManager selfTrustManager = null;
		List<X509Certificate> allIssuers = new ArrayList<X509Certificate>();
		/**
		 * Constructor for EasyX509TrustManager. This Trust manager deals with both Self Signed and 
		 * default code. 
		 */
		public InitialX509TrustManager()
				throws NoSuchAlgorithmException, KeyStoreException{
			super();
			TrustManagerFactory selffactory = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
			selffactory.init((KeyStore) null ); // Initialize TMF with self signed cert keystore	
			TrustManager[] selftm = selffactory.getTrustManagers();
	
			if ( selftm.length == 0 ){
				throw new NoSuchAlgorithmException( "no trust manager found" );
			}
			this.selfTrustManager = (X509TrustManager) selftm[0];
		}

		/**
		 * @see javax.net.ssl.X509TrustManager#checkClientTrusted(X509Certificate[],String authType)
		 */
		public void checkClientTrusted( X509Certificate[] certificates, String authType )
				throws CertificateException{
			try{
				selfTrustManager.checkClientTrusted( certificates, authType );	
			}
			catch(CertificateException e){
				Log.d(TAG,"Exception while initializing TrustManager: checkClientTrusted:"+e);
			}
		}
		/**
		 * @see javax.net.ssl.X509TrustManager#checkServerTrusted(X509Certificate[],String authType)
		 */
		public void checkServerTrusted( X509Certificate[] certificates, String authType )
				throws CertificateException{
			try{
				//selfTrustManager.checkServerTrusted( certificates, authType );	
				maincert=certificates[certificates.length-1];
				//Log.d(TAG, "maincert:"+maincert+" || certificates:"+certificates);
				//Set mykey for future verification
				if (maincert!=null)
				{	
					mykey = KeyStore.getInstance("BKS");
					mykey.load(null, null);
					mykey.setCertificateEntry("MainCert", maincert);
				}
				else
				{
					Log.d(TAG,"Maincert is null while creating keystore for the first time.");
				}
				//Write this cert to the cert file
				try{
					//use buffering
					OutputStream file = new FileOutputStream(rootcertfile);
					OutputStream buffer = new BufferedOutputStream( file );
					ObjectOutput output = new ObjectOutputStream( buffer );
					try{
						output.writeObject(maincert);
					}	
					finally{
						output.close();
					}	
    		    }  
    		    catch(IOException e){
    		      Log.d(TAG,"Cannot write to the rootcertfile."+ e);
    		    }
			}
			catch(CertificateException e)
			{	
				Log.d(TAG,"Exception while initializing TrustManager: checkServerTrusted:"+e);
			} catch (KeyStoreException e) {
				Log.d(TAG,"Exception while initializing TrustManager:"+e);
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				Log.d(TAG,"Exception while initializing TrustManager:"+e);
				e.printStackTrace();
			} catch (IOException e) {
				Log.d(TAG,"Exception while initializing TrustManager:"+e);
				e.printStackTrace();
			}
		}

		/**
		 * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
		 */
		public X509Certificate[] getAcceptedIssuers(){
			return null;
		}
    }
}


