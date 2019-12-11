/*
 * The MIT License
 *
 * Copyright (c) Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.reallypermissivescriptsecurity;

import groovy.lang.Binding;
import hudson.util.RingBufferLogHandler;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.reallypermissivescriptsecurity.ReallyPermissiveWhitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import org.jenkinsci.plugins.scriptsecurity.scripts.ApprovalContext;
import org.jenkinsci.plugins.scriptsecurity.scripts.ClasspathEntry;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ReallyPermissiveWhitelistTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void ignoreSafeSignature() throws Exception {
        try {
            Object ret = runScript("this.equals(this)");
            assertTrue((Boolean) ret);
        } finally {
        }
    }

    @Test
    public void permittedSignaturesAreNotRetained() throws Exception {
        try {
            Object o = runScript("new File('/etc/shadow')");
            assertTrue(o instanceof File);
        } catch (RejectedAccessException _) {
            fail();
        }
    }

    private Object runScript(String text) throws Exception {
        SecureGroovyScript script = new SecureGroovyScript(text, true, Collections.<ClasspathEntry>emptyList());
        script.configuring(ApprovalContext.create());
        return script.evaluate(getClass().getClassLoader(), new Binding());
    }
}
