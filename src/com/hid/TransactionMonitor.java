package com.hid;

import com.hidglobal.ia.service.transaction.Transaction;
@SuppressWarnings({"java:S2446","java:S2274"})
public class TransactionMonitor {
    private Transaction transaction;
    private String consensus;
    private String password;
    private boolean isBiometricEnabled;

    public synchronized void setTransaction(Transaction transaction) {
        this.transaction = transaction;
    }

    public synchronized Transaction getTransaction() {
        return transaction;
    }

    public synchronized void setUserInput(String consensus, String password, boolean isBiometricEnabled) {
        this.consensus = consensus;
        this.password = password;
        this.isBiometricEnabled = isBiometricEnabled;
        notify();
    }

    public synchronized void waitForUserInput() throws InterruptedException {
        wait();
    }

    public String getConsensus() {
        return consensus;
    }

    public String getPassword() {
        return password;
    }

    public boolean isBiometricEnabled() {
        return isBiometricEnabled;
    }

    public synchronized void clear() {
        transaction = null;
        consensus = null;
        password = null;
        isBiometricEnabled = false;
    }
}

