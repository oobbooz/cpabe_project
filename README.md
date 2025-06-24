# **Cryptography Project**
**Project:** *Attribute-Based Data Security Combined with Access Control for Cloud Applications in Small Enterprises*

---

## **Description**

This project provides a secure data-sharing system that enables organizations to encrypt, store, and control access to sensitive documents using a combination of symmetric encryption (**AES-GCM**), attribute-based encryption (**CP-ABE**), and **JSON Web Tokens (JWT)** for authentication and access control.

The system addresses real-world enterprise needs, where documents must be shared among users across different roles, departments, and locations — while preventing unauthorized access, including from cloud service providers.

---

## **Key Features**

- **End-to-End Encryption**  
  Documents are encrypted on the client side using **AES-GCM**, ensuring both confidentiality and integrity.

- **Fine-Grained Access Control**  
  The AES key is encrypted using **CP-ABE** with a user-defined access policy, allowing only those with matching attributes to decrypt.

- **Attribute-Based Access (ABAC)**  
  Enables dynamic and flexible permission control based on user attributes (e.g., role, department, location).

- **Secure Key Distribution**  
  The **Certificate Authority (CA)** issues CP-ABE secret keys only after verifying user identity and attributes via a signed **JWT**.

- **JWT-Based Authentication**  
  JWTs are signed using **ECDSA**, verified server-side, and used for secure identity and access validation.

- **Cloud Integration**  
  Combines **Google Cloud Functions** for access control logic and **Firebase** for secure metadata and document storage.

---

## **Technologies Used**

- **Charm-Crypto** – CP-ABE (AC17 scheme)  
- **PyCryptodome** – AES-GCM symmetric encryption  
- **PyJWT** – JWT signing and verification  
- **OpenSSL** – Certificate and key management (used by CA)  
- **Firebase Admin SDK** – Firestore, Authentication, and Storage  
- **tkinter** – GUI for the client-side application  

This system offers a practical implementation of attribute-based encryption in cloud environments, with strong guarantees of confidentiality, access control, and data integrity.

---

## **Architecture Diagram**

![System Architecture](./resource/architecture.png)

---

## **Demo**

📽️ [Watch Demo on Google Drive](https://drive.google.com/file/d/1Ye6jNHj0Rb4mE2pladXWWg8_LpPnT0ya/view?usp=sharing)

---
