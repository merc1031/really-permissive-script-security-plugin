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

import hudson.Extension;
import org.jenkinsci.plugins.scriptsecurity.sandbox.RejectedAccessException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Permit every access
 *
 * @author merc1031.
 */
@Restricted(NoExternalUse.class)
@Extension(ordinal = Double.MAX_VALUE) // Run if no other whitelist permitted the signature.
public class ReallyPermissiveWhitelist extends Whitelist {
    /*package*/ static final Logger LOGGER = Logger.getLogger(ReallyPermissiveWhitelist.class.getName());

    public boolean permit() {
      return true;
    }

    public boolean permitsMethod(@Nonnull Method method, @Nonnull Object receiver, @Nonnull Object[] args) {
        return permit();
    }

    public boolean permitsConstructor(@Nonnull Constructor<?> constructor, @Nonnull Object[] args) {
        return permit();
    }

    public boolean permitsStaticMethod(@Nonnull Method method, @Nonnull Object[] args) {
        return permit();
    }

    public boolean permitsFieldGet(@Nonnull Field field, @Nonnull Object receiver) {
        return permit();
    }

    public boolean permitsFieldSet(@Nonnull Field field, @Nonnull Object receiver, @CheckForNull Object value) {
        return permit();
    }

    public boolean permitsStaticFieldGet(@Nonnull Field field) {
        return permit();
    }

    public boolean permitsStaticFieldSet(@Nonnull Field field, @CheckForNull Object value) {
        return permit();
    }
}
