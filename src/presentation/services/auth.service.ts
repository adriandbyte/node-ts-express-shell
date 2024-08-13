import { JwtAdapter, bcryptAdapter } from "../../config";
import { UserModel } from "../../data";
import {
  CustomError,
  LoginUserDto,
  RegisterUserDto,
  UserEntity,
} from "../../domain";
import { EmailService, SendMailOptions } from "./email.service";

export class AuthService {
  // DI
  constructor(private readonly emailService: EmailService) {}

  public async registerUser(registerUserDto: RegisterUserDto) {
    const existUser = await UserModel.findOne({ email: registerUserDto.email });
    if (existUser) throw CustomError.badRequest("Email already exist");

    try {
      const user = new UserModel(registerUserDto);

      // Encriptar la contraseña
      user.password = bcryptAdapter.hash(registerUserDto.password);

      await user.save();
      // JWT <---- para mantener la autenticación del usuario
      const token = await JwtAdapter.generateToken({ id: user.id });

      // Email de confirmación
      await this.sendConfirmationEmail(user.email);
      const { password, ...userEntity } = UserEntity.fromObject(user);

      return {
        user: userEntity,
        token: token,
      };
    } catch (error) {
      throw CustomError.internalServer(`${error}`);
    }
  }

  public async loginUser(loginUserDto: LoginUserDto) {
    const user = await UserModel.findOne({ email: loginUserDto.email });
    if (!user) throw CustomError.badRequest("Email not exist");

    const isMatching = bcryptAdapter.compare(
      loginUserDto.password,
      user.password
    );
    if (!isMatching) throw CustomError.badRequest("Password is not valid");

    const { password, ...userEntity } = UserEntity.fromObject(user);

    const token = await JwtAdapter.generateToken({ id: user.id });
    if (!token) throw CustomError.internalServer("Error while creating JWT");

    return {
      user: userEntity,
      token: token,
    };
  }

  private async sendConfirmationEmail(email: string) {
    const token = await JwtAdapter.generateToken({ email });
    if (!token) throw CustomError.internalServer("Error while creating JWT");

    const confirmationLink = `${process.env.WEB_SERVICE_URL}/auth/validate-email/${token}`;
    const html = `
      <h1>Confirm your email</h1>
      <p>Click on the following link to confirm your email</p>
      <a href="${confirmationLink}">Confirm email: ${email}</a>
    `;

    const options : SendMailOptions = {
      to: email,
      subject: "Confirm your email",
      htmlBody: html,
    }

    const isSend = this.emailService.sendEmail(options);
    if(!isSend) throw CustomError.internalServer("Error while sending email");  
    return true; 
  }


  public async validateEmail(token: string) {
    const payload = await JwtAdapter.validateToken(token);
    if(!payload) throw CustomError.badRequest("Invalid token");

    const { email } = payload as { email: string };
    if(!email) throw CustomError.badRequest("Invalid email");

    const user = await UserModel.findOne({ email }); 
    if(!user) throw CustomError.badRequest("Email not exist");

    user.emailValidated = true;
    
    user.save();

    return UserEntity.fromObject(user);
  }
}
